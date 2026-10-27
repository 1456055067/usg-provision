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
# xpr.py plus counts of the one-byte and 16-bit length extensions and
# the bits left after the end symbol. Used for OBS-012 (extension counts)
# and OBS-013 (d).
# Usage: python3 -I xpr2.py [-v] <file>...
#
# Below this header the file is byte-for-byte the script used for R1.
# Own LZ77+Huffman decoder written from specs/standards/wim-compression.md s3
# (summary of [MS-XCA] 2.2.4), instrumented to report chunk framing.
import sys, hashlib
class Bad(Exception): pass
STATS={'ext8':0,'ext16':0}
def u16(b,p):
    if p+2>len(b): raise Bad("read16 past end at %d"%p)
    return b[p]|(b[p+1]<<8)
def decode(inp, outlen, trace):
    out=bytearray(); pos=0; blocks=0
    info={}
    while True:
        if len(out)==outlen and pos==len(inp):
            info['end']='clean-at-block-boundary'; break
        if len(inp)-pos<256:
            if len(out)==outlen: info['end']='tail<256 with output full'; info['tail']=len(inp)-pos; break
            raise Bad("short table")
        tbl=inp[pos:pos+256]; lens=[]
        for b in tbl: lens += [b&15, b>>4]
        dec=[None]*32768; n=0
        for L in range(1,16):
            for s in range(512):
                if lens[s]==L:
                    c=1<<(15-L)
                    if n+c>32768: raise Bad("overfull")
                    for k in range(c): dec[n+k]=s
                    n+=c
        if n!=32768: raise Bad("incomplete %d"%n)
        blocks+=1
        pos+=256
        nb=(u16(inp,pos)<<16)|u16(inp,pos+2); pos+=4; ebc=16
        blockend=len(out)+65536
        last=[]
        while True:
            if len(out)>=blockend: break
            sym=dec[nb>>17]; L=lens[sym]
            nb=(nb<<L)&0xffffffff; ebc-=L
            if ebc<0:
                nb|=u16(inp,pos)<<(-ebc); ebc+=16; pos+=2
            last.append((sym,pos,len(out)))
            if sym<256:
                if len(out)>=outlen:
                    info['after_full']=('literal',sym,pos,len(inp)); raise Bad("overrun literal")
                out.append(sym); continue
            if sym==256 and pos==len(inp) and len(out)==outlen:
                info['end']='symbol256 with all input consumed'; info['blocks']=blocks; info['ebc']=ebc; info['rest']=nb>>(32-ebc) if ebc else 0; info['L256']=lens[256]
                info['last']=last[-3:]; return bytes(out),info
            s=sym-256; ml=s&15; ob=s>>4
            if ml==15:
                if pos>=len(inp): raise Bad("eof extra len")
                ml=inp[pos]; pos+=1; STATS['ext8']+=1
                if ml==255:
                    ml=u16(inp,pos); pos+=2; STATS['ext16']+=1
                    if ml<15: raise Bad("extlen<15")
                    ml-=15
                ml+=15
            ml+=3
            off=((nb>>(32-ob)) if ob else 0)+(1<<ob)
            nb=(nb<<ob)&0xffffffff; ebc-=ob
            if ebc<0:
                nb|=u16(inp,pos)<<(-ebc); ebc+=16; pos+=2
            if off>len(out): raise Bad("offset before start")
            if len(out)+ml>outlen:
                info['after_full']=('match',sym,pos,len(inp),len(out),outlen); raise Bad("overrun match")
            for k in range(ml): out.append(out[-off])
    info['blocks']=blocks
    return bytes(out),info
def rh(b):
    return int.from_bytes(b[0:7],'little'), b[7], int.from_bytes(b[8:16],'little'), int.from_bytes(b[16:24],'little')
def resources(d):
    s,f,o,u=rh(d[48:72]); t=d[o:o+s]
    for i in range(s//50):
        e=t[i*50:(i+1)*50]; S,F,O,U=rh(e[:24]); yield i,S,F,O,U,e[30:50]
verbose='-v' in sys.argv
for p in [a for a in sys.argv[1:] if a!='-v']:
    d=open(p,'rb').read(); print("==",p)
    for i,S,F,O,U,h in resources(d):
        if not F&4: continue
        n=(U+32767)//32768; w=8 if U>0xffffffff else 4
        tabsz=(n-1)*w; tab=[int.from_bytes(d[O+k*w:O+(k+1)*w],'little') for k in range(n-1)]
        starts=[0]+tab; base=O+tabsz; ends=tab+[S-tabsz]
        out=b''; kinds=[]
        for c in range(n):
            exp=32768 if c<n-1 else U-32768*(n-1)
            cs=ends[c]-starts[c]; chunk=d[base+starts[c]:base+ends[c]]
            if cs==exp:
                kinds.append('RAW?%d'%cs); out+=chunk; continue
            try:
                o,info=decode(chunk,exp,verbose)
                kinds.append((cs,exp,info.get('end'),info.get('blocks'),'ebc',info.get('ebc'),'rest',info.get('rest'),'len256',info.get('L256')))
                out+=o
            except Bad as e:
                kinds.append(('ERR',cs,exp,str(e))); out+=b'\0'*exp
        ok=hashlib.sha1(out).digest()==h
        print(f" entry {i} off={O} stored={S} orig={U} flags={F:#x} chunks={n} sha1_match={ok}")
        for k in kinds: print("    ",k)

print('STATS',STATS)
