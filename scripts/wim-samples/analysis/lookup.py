# R1 analysis tool (CR-602), kept as run for docs/formats/wim-observed.md.
#
# Only sources: specs/standards/wim.md (sections 2 to 5) and
# specs/standards/wim-compression.md (section 3, the summary of [MS-XCA]
# 2.2.4), plus the R1 sample files themselves. Written on the clean side;
# no third-party WIM, XPRESS, LZX or LZMS code, documentation or test data
# was read or compared against (decision 0006 item 2).
#
# Run: R1 = wim-samples workflow run 40535666995, attempt 1, commit
# ba23bedea96e5d1c68c8f77e8bff4ce9cb012825. Samples are never committed
# (OPEN-PE-LIC); pass their paths as arguments.
#
# Walks a WIM file's lookup table (header resource header at offset 48,
# 50-byte entries) and prints every entry. Used for OBS-007, OBS-008,
# OBS-009, OBS-010, OBS-016 and OBS-017.
# Usage: python3 -I lookup.py <file.wim|.swm|.esd>...
#
# Below this header the file is byte-for-byte the script used for R1.
import sys, struct
def rh(b):
    size = int.from_bytes(b[0:7],'little'); fl=b[7]
    off = int.from_bytes(b[8:16],'little'); orig=int.from_bytes(b[16:24],'little')
    return size, fl, off, orig
for p in sys.argv[1:]:
    d=open(p,'rb').read()
    print("==",p,"len",len(d))
    s,f,o,u = rh(d[48:72])
    print("lookup", s,hex(f),o,u, "entries", s/50)
    t=d[o:o+s]
    for i in range(s//50):
        e=t[i*50:(i+1)*50]
        S,F,O,U=rh(e[:24]); part=int.from_bytes(e[24:26],'little'); rc=int.from_bytes(e[26:30],'little'); h=e[30:50].hex()
        print(f"{i:3d} @{o+i*50:8d} size={S:8d} fl={F:#04x} off={O:8d} orig={U:8d} part={part} rc={rc} sha1={h}")
