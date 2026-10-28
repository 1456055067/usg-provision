# R2 analysis tool, kept as run for docs/formats/wim-observed.md.
#
# Only sources: specs/standards/wim.md (sections 2, 3 and 5), plus the R2
# sample files themselves. Written on the clean side; no third-party WIM,
# XPRESS, LZX or LZMS code, documentation or test data was read or compared
# against (decision 0006 item 2).
#
# Run: R2 = wim-samples workflow run 40599556702, attempt 1, commit
# 5d3c8c701506ff780ff8a86c5e692f725634a6bd. Samples are never committed
# (OPEN-PE-LIC); pass their paths as arguments.
#
# Sorts every range named by the header (lookup table, XML, integrity
# table) and the lookup table, and prints the unnamed ranges ("GAP") and
# any range starting before the previous one ended ("OVERLAP"). Used for
# OBS-018, OBS-020, OBS-021 and OBS-022.
# Usage: python3 -I gaps.py <file.wim>...
#
# Below this header the file is byte-for-byte the script used for R2.
import sys
def rh(b):
    return int.from_bytes(b[0:7],'little'),b[7],int.from_bytes(b[8:16],'little'),int.from_bytes(b[16:24],'little')
for p in sys.argv[1:]:
    d=open(p,'rb').read()
    L=rh(d[48:72]); X=rh(d[72:96]); I=rh(d[124:148])
    rs=[]
    t=d[L[2]:L[2]+L[0]]
    for i in range(L[0]//50):
        e=t[i*50:i*50+50]; S,F,O,U=rh(e[:24]); rs.append((O,S,f"e{i} fl={F:#x} rc={int.from_bytes(e[26:30],'little')} sha={e[30:34].hex()}"))
    rs.append((L[2],L[0],"LOOKUP")); rs.append((X[2],X[0],"XML"))
    if I[0]: rs.append((I[2],I[0],"INTEGRITY"))
    rs.sort()
    end=208; print("==",p.split('/')[-1],"len",len(d))
    for O,S,n in rs:
        if O>end: print(f"  GAP {end}..{O} ({O-end} bytes)")
        if O<end: print(f"  OVERLAP at {O} (end so far {end}) {n}")
        end=max(end,O+S)
    if end<len(d): print(f"  TAIL GAP {end}..{len(d)}")
    print("  last 6 by offset:"); [print("   ",r) for r in rs[-6:]]
