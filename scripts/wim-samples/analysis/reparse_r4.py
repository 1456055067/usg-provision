# R4 analysis tool (M3 WU-W3 round 2), kept as run for
# docs/formats/wim-observed.md.
#
# Only sources: specs/standards/reparse-and-security-descriptors.md
# sections 2 to 5 (our AUDITED summary of [MS-FSCC] REPARSE_DATA_BUFFER,
# the symbolic link and mount point buffers, and path names), the
# dentry_r3.py output for a WIM ("E" lines: the tag at +88; "R" lines: the
# stored reparse resource), and the text Windows' own "fsutil reparsepoint
# query" printed on the runner (<tree>.reparse.txt). Written on the clean
# side; no third-party WIM code, documentation or test data was read,
# recalled or compared against (decision 0006 item 2).
#
# Run: R4 = wim-samples workflow run 40766748266, attempt 1, commit
# 4ba76cd6fb9c65b3782e47e6a176e8e248c01a61.
#
# Each input holds a reparse DataBuffer as the summary's section 2 defines
# it: the bytes after the 8-byte header, so it starts with
# SubstituteNameOffset. fsutil prints the tag and ReparseDataLength
# separately and the DataBuffer as "Reparse Data"; the WIM stores the
# same span (OBS-036). The decode, per sections 3 and 4:
#   +0 SubstituteNameOffset (2), +2 SubstituteNameLength (2),
#   +4 PrintNameOffset (2), +6 PrintNameLength (2),
#   symbolic link (tag 0xA000000C): +8 Flags (4), PathBuffer at +12;
#   mount point (tag 0xA0000003): PathBuffer at +8.
# Offsets are from the start of PathBuffer; lengths in bytes, no null.
# Every offset and length is checked against the buffer (section 5).
#
# Usage: python3 -I reparse_r4.py TAGS LABEL=FILE [LABEL=FILE ...]
#   TAGS: a dentry_r3.py output (E lines give each path's tag)
#   FILE: a dentry_r3.py output (its R lines) or a .reparse.txt file
# Prints, per path, one line per input: names with offsets and lengths.
import re
import sys

SYMLINK = 0xA000000C
MOUNT = 0xA0000003


def load_tags(path):
    tags = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            c = line.rstrip("\n").split("\t")
            if c[0] == "E" and len(c) > 11 and c[11].startswith("union="):
                u = bytes.fromhex(c[11][6:])
                tags[c[2]] = int.from_bytes(u[0:4], "little")
    return tags


def load(path):
    out = {}
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if re.search(r"^R\t", text, re.M):
        for line in text.splitlines():
            c = line.split("\t")
            if c[0] == "R" and len(c) == 4:
                out[c[1]] = bytes.fromhex(c[3].replace(" ", ""))
        return out
    cur = None
    for line in text.splitlines():
        m = re.match(r"== \S+ (.*) \(exit", line)
        if m:
            cur = m.group(1)
            out[cur] = bytearray()
            continue
        if cur is not None and re.match(r"^[0-9a-f]{4}:  ", line):
            toks = [t for t in line[7:56].split() if re.fullmatch(r"[0-9a-f]{2}", t)]
            out[cur] += bytes.fromhex("".join(toks))
    return {k: bytes(v) for k, v in out.items()}


def u16(b, o):
    if o + 2 > len(b):
        raise ValueError("short buffer")
    return int.from_bytes(b[o:o + 2], "little")


def decode(tag, b):
    sno, snl, pno, pnl = u16(b, 0), u16(b, 2), u16(b, 4), u16(b, 6)
    if tag == SYMLINK:
        if len(b) < 12:
            raise ValueError("symbolic link buffer under 12 bytes")
        flags = int.from_bytes(b[8:12], "little")
        base = 12
    elif tag == MOUNT:
        flags = None
        base = 8
    else:
        raise ValueError("tag 0x%08x not decoded" % tag)
    pb = b[base:]
    for o, n in ((sno, snl), (pno, pnl)):
        if o % 2 or n % 2 or o + n > len(pb):
            raise ValueError("name (%d, %d) outside PathBuffer of %d" % (o, n, len(pb)))
    sub = pb[sno:sno + snl].decode("utf-16-le")
    prn = pb[pno:pno + pnl].decode("utf-16-le")
    extra = len(pb) - max(sno + snl, pno + pnl)
    return ("len=%d flags=%s sub@%d+%d=%r print@%d+%d=%r tail=%d"
            % (len(b), "-" if flags is None else flags, sno, snl, sub, pno, pnl, prn, extra))


def main():
    if len(sys.argv) < 3:
        sys.exit("usage: reparse_r4.py TAGS LABEL=FILE ...")
    tags = load_tags(sys.argv[1])
    inputs = []
    for arg in sys.argv[2:]:
        label, _, path = arg.partition("=")
        inputs.append((label, load(path)))
    for p in sorted(tags):
        if tags[p] not in (SYMLINK, MOUNT):
            continue
        print("%s (tag 0x%08x)" % (p, tags[p]))
        for label, data in inputs:
            b = data.get(p)
            if b is None:
                print("  %-8s (absent)" % label)
                continue
            try:
                print("  %-8s %s" % (label, decode(tags[p], b)))
            except ValueError as e:
                print("  %-8s ERROR %s" % (label, e))


if __name__ == "__main__":
    main()
