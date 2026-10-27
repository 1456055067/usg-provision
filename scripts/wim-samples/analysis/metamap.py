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
# Decodes every metadata resource of a WIM (with xpr.py's decoder) and
# reports which source tree's bin\random-1.bin SHA-1 (from the run's
# trees.txt) it contains. Used for OBS-009 (k-th metadata entry = index k).
# Usage: python3 -I metamap.py <path to xpr.py> <S04.wim> <trees.txt>
#
# Below this header the file is byte-for-byte the script used for R1.
import sys, re, importlib.util
spec=importlib.util.spec_from_file_location("xpr", sys.argv[1]); 
src=open(sys.argv[1]).read().split("verbose='-v'")[0]
ns={}; exec(src, ns)
d=open(sys.argv[2],'rb').read()
trees={}
for line in open(sys.argv[3],encoding='utf-8'):
    m=re.match(r'== tree (\S+) ==',line)
    if m: cur=m.group(1)
    m=re.search(r'bin\\random-1\.bin\s+length=1\s+sha1=([0-9a-f]+)',line)
    if m: trees[cur]=bytes.fromhex(m.group(1))
for i,S,F,O,U,h in ns['resources'](d):
    if not F&2: continue
    chunk=d[O:O+S]
    if F&4:
        out,info=ns['decode'](chunk,U,False)
    else: out=chunk
    hit=[t for t,s in trees.items() if s in out]
    print(i,"offset",O,"tree",hit)
