# R2 analysis tool, kept as run for docs/formats/wim-observed.md.
#
# Only sources: specs/standards/wim.md (sections 2 to 5) and
# specs/standards/wim-compression.md (section 3), through xpr.py's
# decoder, plus the R2 sample files and trees.txt. Written on the clean
# side; no third-party WIM, XPRESS, LZX or LZMS code, documentation or
# test data was read or compared against (decision 0006 item 2).
#
# Run: R2 = wim-samples workflow run 40599556702, attempt 1, commit
# 5d3c8c701506ff780ff8a86c5e692f725634a6bd. Samples are never committed
# (OPEN-PE-LIC); pass their paths as arguments.
#
# Decodes every metadata resource of a WIM, checks it against the lookup
# SHA-1, reports which tree-service files (SHA-1 from R2 trees.txt) it
# holds, and prints the XML index-to-name pairs. Used for OBS-021.
# Usage: python3 -I metahash.py <path to xpr.py> <file.wim>
#
# Below this header the file is byte-for-byte the script used for R2.
import sys, re, hashlib
src=open(sys.argv[1]).read().split("verbose='-v'")[0]
ns={}; exec(src, ns)
d=open(sys.argv[2],'rb').read()
want={'serviced.txt':bytes.fromhex('a8ccfd6b9fbdef57136770883b09644229ec0cf0'),'serviced-40000.bin':bytes.fromhex('880baf1cf22d633e62c840feb2a975bd7992775b')}
for i,S,F,O,U,h in ns['resources'](d):
    if not F&2: continue
    out,info=ns['decode'](d[O:O+S],U,False)
    print(i,O,"sha1 ok" if hashlib.sha1(out).digest()==h else "SHA1 MISMATCH",[k for k,v in want.items() if v in out])
def rh(o):
    b=d[o:o+24]; return int.from_bytes(b[0:7],'little'),int.from_bytes(b[8:16],'little')
s,o=rh(72); x=d[o+2:o+s].decode('utf-16-le')
print(re.findall(r'<IMAGE INDEX="(\d+)">.*?<NAME>([^<]*)</NAME>',x))
