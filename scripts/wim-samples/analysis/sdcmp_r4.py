# R4 analysis tool (M3 WU-W3 round 2), kept as run for
# docs/formats/wim-observed.md.
#
# Only sources: specs/standards/wim.md section 2 (the lookup table's
# resource header at offset 48), section 3 (resource header: 7-byte
# stored size, flag byte, offset) and section 5 (50-byte lookup entries,
# metadata flag 0x02, compressed flag 0x04), with
# docs/formats/wim-observed.md OBS-007 and OBS-008 (those layouts as
# observed); OBS-024 (security block layout) and OBS-026 (entries,
# through dentry_r3.py's output);
# specs/standards/reparse-and-security-descriptors.md section 9 (our
# AUDITED summary of the [MS-DTYP] self-relative descriptor: fixed part
# and Control flags), and the tree manifests Build-Samples.ps1 writes
# (column sd-binary: .NET's Get-Acl GetSecurityDescriptorBinaryForm(),
# a re-serialisation, not the bytes Windows returned). Written on the
# clean side; no third-party WIM code, documentation or test data was
# read, recalled or compared against (decision 0006 item 2).
#
# Run: R4 = wim-samples workflow run 40766748266, attempt 1, commit
# 4ba76cd6fb9c65b3782e47e6a176e8e248c01a61.
#
# For an uncompressed single-image WIM: prints each stored descriptor's
# length, the 20-byte fixed part read per section 9 (Revision, Control,
# the four offsets) and the Control flag names; then, for each manifest
# row with an sd-binary value, whether it equals the stored descriptor
# the entry's security index names. Used for OBS-054.
# The file is read up to 1 GiB (1 << 30 bytes): enough for the R4
# metadata samples, and a bound on memory. Anything the lookup table
# points at beyond what was read fails with "read past end"; nothing is
# guessed.
# Usage: python3 -I sdcmp_r4.py <file.wim> <dentry_r3 output> <manifest.tsv>
import sys

FLAGS = [(0x8000, "SR"), (0x4000, "RM"), (0x2000, "PS"), (0x1000, "PD"),
         (0x0800, "SI"), (0x0400, "DI"), (0x0200, "SC"), (0x0100, "DC"),
         (0x0080, "SS"), (0x0040, "DT"), (0x0020, "SD"), (0x0010, "SP"),
         (0x0008, "DD"), (0x0004, "DP"), (0x0002, "GD"), (0x0001, "OD")]


def u(b, o, n):
    if o + n > len(b):
        raise SystemExit("read past end")
    return int.from_bytes(b[o:o + n], "little")


def main():
    if len(sys.argv) != 4:
        sys.exit("usage: sdcmp_r4.py file.wim dentry_r3.txt manifest.tsv")
    with open(sys.argv[1], "rb") as f:
        d = f.read(1 << 30)
    ls, lo = u(d, 48, 7), u(d, 56, 8)
    meta = None
    for i in range(ls // 50):
        e = d[lo + i * 50:lo + i * 50 + 50]
        if e[7] & 0x02:
            if e[7] & 0x04:
                raise SystemExit("compressed metadata; this tool reads uncompressed files only")
            s, o = u(e, 0, 7), u(e, 8, 8)
            meta = d[o:o + s]
            break
    if meta is None:
        raise SystemExit("no metadata entry")
    count = u(meta, 4, 4)
    pos = 8 + 8 * count
    sds = []
    for k in range(count):
        n = u(meta, 8 + 8 * k, 8)
        sds.append(bytes(meta[pos:pos + n]))
        pos += n
    for k, sd in enumerate(sds):
        ctl = u(sd, 2, 2)
        names = "|".join(n for m, n in FLAGS if ctl & m)
        print("SD[%d] len %d revision %d control 0x%04x [%s] owner@%d group@%d sacl@%d dacl@%d"
              % (k, len(sd), sd[0], ctl, names, u(sd, 4, 4), u(sd, 8, 4), u(sd, 12, 4), u(sd, 16, 4)))
    sec = {}
    with open(sys.argv[2], encoding="utf-8") as f:
        for line in f:
            c = line.rstrip("\n").split("\t")
            if c[0] == "E":
                sec[c[2]] = int(c[4][4:])
    with open(sys.argv[3], encoding="utf-8") as f:
        head = f.readline().rstrip("\n").split("\t")
        if "sd-binary" not in head:
            raise SystemExit("manifest has no sd-binary column")
        col = head.index("sd-binary")
        eq = ne = 0
        only_ctl = {}
        for line in f:
            c = line.rstrip("\n").split("\t")
            p, v = c[0], c[col]
            if v == "-" or p not in sec:
                continue
            k = sec[p]
            b = bytes.fromhex(v)
            same = 0 <= k < len(sds) and b == sds[k]
            eq += same
            ne += not same
            if not same and 0 <= k < len(sds) and len(b) == len(sds[k]):
                pos = [i for i in range(len(b)) if b[i] != sds[k][i]]
                key = (u(b, 2, 2), u(sds[k], 2, 2), tuple(pos))
                only_ctl.setdefault(key, []).append(p)
            elif not same:
                print("DIFF %s index %d: manifest len %d; stored len %d" % (p, k, len(b), len(sds[k]) if 0 <= k < len(sds) else -1))
        print("sd-binary equal to the stored descriptor: %d; differ: %d" % (eq, ne))
        for (mc, sc, pos), ps in sorted(only_ctl.items()):
            print("  same length, differing byte offsets %s: manifest control 0x%04x, stored 0x%04x: %d rows (e.g. %s)"
                  % (list(pos), mc, sc, len(ps), ps[0]))


if __name__ == "__main__":
    main()
