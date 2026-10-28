# R3 analysis tool (M3 WU-W3), kept as run for docs/formats/wim-observed.md.
#
# Only sources: dentry_r3.py's output ("R" lines: the bytes of the
# resource named by a reparse point's hashes) and the text that
# Build-Samples.ps1 records from Windows' own "fsutil reparsepoint query"
# (<tree>.reparse.txt), both from the R3 artifacts. No WIM layout or
# reparse-buffer knowledge is used: bytes are compared as they are.
# Written on the clean side; no third-party WIM code, documentation or test
# data was read, recalled or compared against (decision 0006 item 2).
#
# Run: R3 = wim-samples workflow run 40754869824, attempt 1, commit
# 27f7237d99c67a9cc575268398dd4193ae1fbccf.
#
# For each reparse point, compares the stored resource with fsutil's
# "Reparse Data" bytes on the capture source and on DISM's applied tree.
# Used for OBS-033 (M-13).
# Usage: python3 -I reparsecmp.py <dentry_r3 output> <source.reparse.txt>
#                                 <applied.reparse.txt>
import re
import sys


def stored(path):
    out = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            c = line.rstrip("\n").split("\t")
            if c[0] == "R" and len(c) == 4:
                out[c[1]] = bytes.fromhex(c[3].replace(" ", ""))
    return out


def fsutil(path):
    data, lens, cur = {}, {}, None
    with open(path, encoding="utf-8") as f:
        for line in f:
            m = re.match(r"== \S+ (.*) \(exit", line)
            if m:
                cur = m.group(1)
                data[cur] = bytearray()
                continue
            m = re.match(r"Reparse Data Length: (0x[0-9a-fA-F]+)", line)
            if m and cur is not None:
                lens[cur] = int(m.group(1), 16)
            if cur is not None and re.match(r"^[0-9a-f]{4}:  ", line):
                # Hex column only: "oooo:  " then 16 two-digit tokens; the
                # ASCII column after it is ignored.
                toks = [t for t in line[7:56].split() if re.fullmatch(r"[0-9a-f]{2}", t)]
                data[cur] += bytes.fromhex("".join(toks))
    return data, lens


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__ or "usage: reparsecmp.py dentry.txt source.reparse.txt applied.reparse.txt")
    w = stored(sys.argv[1])
    s, sl = fsutil(sys.argv[2])
    a, al = fsutil(sys.argv[3])
    for k in sorted(w):
        sb, ab = bytes(s.get(k, b"")), bytes(a.get(k, b""))
        print("%s: stored %d; source %d (length field %s); applied %d (length field %s); "
              "stored==source %s; stored==applied %s"
              % (k, len(w[k]), len(sb), sl.get(k), len(ab), al.get(k), w[k] == sb, w[k] == ab))


if __name__ == "__main__":
    main()
