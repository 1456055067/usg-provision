# R3 analysis tool (M3 WU-W3), kept as run for docs/formats/wim-observed.md.
#
# Only sources: specs/standards/wim.md sections 2, 3, 5 and 6 (our summary
# of Microsoft's WIM paper) and the bytes of the R3 sample files, read with
# dentry.py and its hex output. Written on the clean side; no third-party
# WIM, XPRESS, LZX or LZMS code, documentation or test data was read,
# recalled or compared against (decision 0006 item 2).
#
# Run: R3 = wim-samples workflow run 40754869824, attempt 1, commit
# 27f7237d99c67a9cc575268398dd4193ae1fbccf. Samples are never committed
# (OPEN-PE-LIC); pass their paths as arguments.
#
# Why this file exists: dentry.py reads the entry with wim.md section 6's
# 98-byte fixed part and found that it fits none of the R3 entries (its
# output: "length 40 out of range", every name empty). The bytes of S01 and
# S13 show the name length at +100 and the name at +102 instead (OBS-026).
# This walker reads the entry the way the R3 bytes show it, and checks
# every assumption against each entry, printing "MISFIT" where one fails:
#   +0 length (8)          +8 attributes (4)      +12 security index (4)
#   +16 children offset (8) +24 (8) +32 (8)       +40 +48 +56 times (8 each)
#   +64 hash (20)          +84 (4)                +88 union (8)
#   +96 stream count (2)   +98 short name length (2)
#   +100 name length (2)   +102 name, 2 zero bytes, short name, 2 zero
#   bytes (only when the short name length is non-zero), zero padding;
#   length = the used size rounded up to 8.
#   stream entry: +0 length (8), +8 (8), +16 hash (20), +36 name length
#   (2), +38 name, 2 zero bytes, zero padding to the length; stream entries
#   directly follow their entry, in count; the next entry follows them.
# What a field means is not decided here; it is printed for the record.
#
# With --manifest (a tree manifest from Build-Samples.ps1) it compares each
# entry with the manifest row of the same path: attributes, times, sizes,
# named streams and, for an uncompressed file (S13, S15), the SHA-256 of
# the resource named by the hash. With --resource-hex it prints the bytes
# of the resource named by each reparse point's hashes.
#
# Usage: python3 -I dentry_r3.py [--manifest M] [--prefix P] [--resource-hex]
#                                [--xpr xpr.py] <file.wim>
#   --prefix: a path prefix to strip from WIM paths before matching the
#   manifest (S15: "tree-meta\" is matched against tree-meta's manifest).
import argparse
import hashlib
import sys

FIXED = 102
SFIXED = 38
MAX_FILE = 1 << 30
MAX_META = 256 << 20
MAX_ENTRIES = 500000
MAX_DEPTH = 1024
CHUNK = 32768


class Bad(Exception):
    pass


def u(b, o, n):
    if o < 0 or o + n > len(b):
        raise Bad("read %d at %d past end %d" % (n, o, len(b)))
    return int.from_bytes(b[o:o + n], "little")


def rh(b, o):
    return (u(b, o, 7), b[o + 7], u(b, o + 8, 8), u(b, o + 16, 8))


def al8(n):
    return (n + 7) // 8 * 8


def load_xpr(path):
    with open(path, encoding="utf-8") as f:
        src = f.read().split("verbose='-v'")[0]
    ns = {}
    exec(src, ns)
    return ns


def res_bytes(d, r, xpr):
    S, F, O, U = r
    if O > len(d) or S > len(d) - O or U > MAX_META:
        raise Bad("resource outside the file or over the cap")
    raw = d[O:O + S]
    if not F & 0x04:
        return raw
    if xpr is None:
        raise Bad("compressed; pass --xpr")
    n = (U + CHUNK - 1) // CHUNK
    starts = [0] + [u(raw, k * 4, 4) for k in range(n - 1)]
    data = raw[(n - 1) * 4:]
    ends = starts[1:] + [len(data)]
    out = bytearray()
    for c in range(n):
        exp = CHUNK if c < n - 1 else U - CHUNK * (n - 1)
        if not starts[c] < ends[c] <= len(data):
            raise Bad("chunk %d bounds" % c)
        if ends[c] - starts[c] == exp:
            raise Bad("chunk %d stored size equals expanded size (OPEN-WIM-5)" % c)
        o, _ = xpr["decode"](data[starts[c]:ends[c]], exp, False)
        out += o
    return bytes(out)


def name16(b):
    try:
        return b.decode("utf-16-le")
    except UnicodeDecodeError:
        return "<bad UTF-16 %s>" % b.hex()


class Entry:
    pass


def parse_entry(m, o, misfits):
    e = Entry()
    e.off = o
    e.length = u(m, o, 8)
    if e.length == 0:
        return None
    if e.length < FIXED or e.length > len(m) - o:
        raise Bad("entry @%d length %d out of range" % (o, e.length))
    e.attr = u(m, o + 8, 4)
    e.sec = int.from_bytes(m[o + 12:o + 16], "little", signed=True)
    e.sub = u(m, o + 16, 8)
    e.f24 = u(m, o + 24, 8)
    e.f32 = u(m, o + 32, 8)
    e.t = (u(m, o + 40, 8), u(m, o + 48, 8), u(m, o + 56, 8))
    e.hash = bytes(m[o + 64:o + 84])
    e.f84 = u(m, o + 84, 4)
    e.union = bytes(m[o + 88:o + 96])
    e.nstr = u(m, o + 96, 2)
    e.slen = u(m, o + 98, 2)
    e.nlen = u(m, o + 100, 2)
    p = o + FIXED
    e.name = name16(m[p:p + e.nlen])
    p += e.nlen
    term = m[p:p + 2]
    p += 2
    e.short = name16(m[p:p + e.slen]) if e.slen else ""
    if e.slen:
        p += e.slen
        sterm = m[p:p + 2]
        p += 2
    else:
        sterm = b"\0\0"
    used = p - o
    pad = m[p:o + e.length]
    why = []
    if e.nlen % 2 or e.slen % 2:
        why.append("odd name length")
    if term != b"\0\0" or sterm != b"\0\0":
        why.append("terminator not zero")
    if e.length != al8(used):
        why.append("length %d != align8(used %d)" % (e.length, used))
    if any(pad):
        why.append("non-zero padding %s" % pad.hex())
    if why:
        misfits.append("entry @%d %r: %s" % (o, e.name, "; ".join(why)))
    e.streams = []
    q = o + e.length
    for k in range(e.nstr):
        sl = u(m, q, 8)
        if sl < SFIXED or sl > len(m) - q:
            raise Bad("stream @%d length %d out of range" % (q, sl))
        s = Entry()
        s.off = q
        s.length = sl
        s.f8 = u(m, q + 8, 8)
        s.hash = bytes(m[q + 16:q + 36])
        s.nlen = u(m, q + 36, 2)
        s.name = name16(m[q + 38:q + 38 + s.nlen])
        sused = 38 + s.nlen + 2
        sw = []
        if m[q + 38 + s.nlen:q + sused] != b"\0\0":
            sw.append("terminator not zero")
        if sl != al8(sused):
            sw.append("length %d != align8(used %d)" % (sl, sused))
        if any(m[q + sused:q + sl]):
            sw.append("non-zero padding")
        if sw:
            misfits.append("stream @%d %r: %s" % (q, s.name, "; ".join(sw)))
        e.streams.append(s)
        q += sl
    e.end = q
    return e


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("wim")
    ap.add_argument("--manifest")
    ap.add_argument("--prefix", default="")
    ap.add_argument("--resource-hex", action="store_true")
    ap.add_argument("--xpr")
    a = ap.parse_args()
    with open(a.wim, "rb") as f:
        d = f.read(MAX_FILE + 1)
    if len(d) > MAX_FILE or len(d) < 208 or d[:5] != b"MSWIM":
        sys.exit("not a usable WIM")
    xpr = load_xpr(a.xpr) if a.xpr else None
    L = rh(d, 48)
    if L[2] > len(d) or L[0] > len(d) - L[2] or L[0] % 50:
        sys.exit("lookup table unusable")
    lookup, meta = {}, []
    for i in range(L[0] // 50):
        o = L[2] + i * 50
        r = rh(d, o)
        h = bytes(d[o + 30:o + 50])
        if r[1] & 0x02:
            meta.append((i, r, h))
        else:
            lookup.setdefault(h, r)
    if len(meta) != 1:
        sys.exit("this tool reads single-image files only (%d metadata entries)" % len(meta))
    _, r, h = meta[0]
    m = res_bytes(d, r, xpr)
    print("== %s metadata %d bytes sha1 %s (lookup %s)"
          % (a.wim, len(m), hashlib.sha1(m).hexdigest(), h.hex()))
    total, count = u(m, 0, 4), u(m, 4, 4)
    lens = [u(m, 8 + 8 * k, 8) for k in range(count)]
    pos = 8 + 8 * count
    sds = []
    for n in lens:
        if n > len(m) - pos:
            sys.exit("security descriptor past end")
        sds.append(bytes(m[pos:pos + n]))
        pos += n
    print("security: total field %d, count %d, end %d, root at %d" % (total, count, pos, al8(pos)))
    for k, sd in enumerate(sds):
        print("  SD[%d] length %d sha256 %s first 4 bytes %s"
              % (k, len(sd), hashlib.sha256(sd).hexdigest()[:16], sd[:4].hex(" ")))
    misfits = []
    root = parse_entry(m, al8(pos), misfits)
    entries = [(root, "", 0, None)]
    lists = []
    order = {}
    if root.sub:
        lists.append((root.sub, "", 1))
    seen = set()
    while lists:
        off, path, depth = lists.pop()
        if depth > MAX_DEPTH or off in seen:
            misfits.append("list @%d revisited or too deep" % off)
            continue
        seen.add(off)
        q = off
        names = []
        while True:
            if len(entries) > MAX_ENTRIES:
                sys.exit("entry limit")
            e = parse_entry(m, q, misfits)
            if e is None:
                print("END @%d list of %r" % (q, path or "\\"))
                break
            full = e.name if not path else path + "\\" + e.name
            entries.append((e, full, depth, off))
            names.append(e.name)
            if e.sub:
                lists.append((e.sub, full, depth + 1))
            q = e.end
        order[path] = names
    for e, full, depth, lst in entries:
        hn = "zero" if not any(e.hash) else ("lookup %d" % lookup[e.hash][3] if e.hash in lookup else "NOT IN LOOKUP")
        print("E\t%d\t%s\tattr=0x%08x\tsec=%d\tsub=%d\tf24=%d\tf32=%d\tt=%d,%d,%d\thash=%s(%s)\tf84=%d\tunion=%s\tnstr=%d\tshort=%s\tlen=%d"
              % (e.off, full or ".", e.attr, e.sec, e.sub, e.f24, e.f32, e.t[0], e.t[1], e.t[2],
                 e.hash.hex()[:12], hn, e.f84, e.union.hex(), e.nstr, e.short or "-", e.length))
        for s in e.streams:
            sn = "zero" if not any(s.hash) else ("lookup %d" % lookup[s.hash][3] if s.hash in lookup else "NOT IN LOOKUP")
            print("S\t%d\t%s\tname=%s\tf8=%d\thash=%s(%s)\tlen=%d"
                  % (s.off, full or ".", s.name or "(unnamed)", s.f8, s.hash.hex()[:12], sn, s.length))
        if a.resource_hex and e.union[:4] != b"\0\0\0\0" and e.attr & 0x400:
            for tag, hh in [("entry hash", e.hash)] + [("stream %r" % s.name, s.hash) for s in e.streams]:
                if hh in lookup:
                    print("R\t%s\t%s\t%s" % (full, tag, res_bytes(d, lookup[hh], xpr).hex(" ")))
    print("\nmisfits: %d" % len(misfits))
    for x in misfits[:50]:
        print("  MISFIT " + x)
    def nz(f):
        return sum(1 for e, *_ in entries if f(e))
    print("entries %d; non-zero +24: %d; +32: %d; +84: %d; security -1: %d; lengths not multiple of 8: %d"
          % (len(entries), nz(lambda e: e.f24), nz(lambda e: e.f32), nz(lambda e: e.f84),
             nz(lambda e: e.sec == -1), nz(lambda e: e.length % 8)))
    print("security indexes used: %s" % sorted({e.sec for e, *_ in entries}))
    # Sibling order (M-17): compared with candidate orders; none assumed.
    # "split" = entries without a children offset first, then entries with
    # one, each group in upper-case-folded name order.
    kinds = {"ordinal": 0, "upper-case": 0, "split": 0}
    lists_n = 0
    for path, names in order.items():
        es = [(e, full) for e, full, depth, lst in entries[1:]
              if (full.rsplit("\\", 1)[0] if "\\" in full else "") == path]
        nm = [e.name for e, _ in es]
        if nm != names:
            continue
        lists_n += 1
        kinds["ordinal"] += nm == sorted(nm)
        kinds["upper-case"] += nm == sorted(nm, key=lambda s: s.upper())
        split = sorted(es, key=lambda t: (t[0].sub != 0, t[0].name.upper()))
        ok = [e.name for e, _ in split] == nm
        kinds["split"] += ok
        if not ok or len(names) > 50:
            print("order of %r (%d entries): ordinal %s; upper-case %s; split %s; first %s"
                  % (path, len(names), nm == sorted(nm),
                     nm == sorted(nm, key=lambda s: s.upper()), ok, names[:6]))
    print("lists %d; in ordinal order %d; in upper-case order %d; in split order %d"
          % (lists_n, kinds["ordinal"], kinds["upper-case"], kinds["split"]))
    if a.manifest:
        compare(a, d, entries, lookup, xpr)


def compare(a, d, entries, lookup, xpr):
    rows = {}
    with open(a.manifest, encoding="utf-8") as f:
        head = f.readline().rstrip("\n").split("\t")
        for line in f:
            c = line.rstrip("\n").split("\t")
            rows[c[0]] = dict(zip(head, c))
    pre = a.prefix
    stats = {}
    diffs = []

    def bump(k, ok):
        t = stats.setdefault(k, [0, 0])
        t[0 if ok else 1] += 1

    matched = 0
    for e, full, depth, lst in entries:
        p = full or "."
        if pre:
            if p == pre.rstrip("\\"):
                p = "."
            elif p.startswith(pre):
                p = p[len(pre):]
            else:
                continue
        r = rows.get(p)
        if r is None:
            diffs.append("no manifest row for %r" % p)
            continue
        matched += 1
        ma = int(r["attributes"], 16)
        bump("attributes", ma == e.attr)
        if ma != e.attr:
            diffs.append("%s attributes wim 0x%08x manifest 0x%08x" % (p, e.attr, ma))
        for i, col in enumerate(("creation", "last-access", "last-write")):
            ok = r[col] == str(e.t[i])
            bump("time +%d = %s" % (40 + 8 * i, col), ok)
        named = sorted((s.name, s) for s in e.streams if s.name)
        want = r["streams"]
        got = ";".join("%s:%d" % (n, lookup[s.hash][3] if s.hash in lookup else 0) for n, s in named) or "-"
        wn = ";".join(":".join(x.split(":")[:2]) for x in want.split(";")) if want not in ("-",) and not want.startswith("error") else want
        bump("named streams (name:size)", got == wn)
        if got != wn:
            diffs.append("%s streams wim %s manifest %s" % (p, got, wn))
        if r["type"] == "file" and r["sha256"] not in ("-",) and not r["sha256"].startswith("error"):
            h = e.hash
            unnamed = [s for s in e.streams if not s.name]
            if not any(h) and unnamed:
                h = unnamed[0].hash
            if not any(h):
                ok = r["length"] == "0"
            elif h in lookup:
                try:
                    ok = hashlib.sha256(res_bytes(d, lookup[h], xpr)).hexdigest() == r["sha256"]
                except Bad:
                    ok = None
            else:
                ok = False
            if ok is not None:
                bump("file content sha256", ok)
                if not ok:
                    diffs.append("%s content differs" % p)
    print("\ncompare with %s: %d entries matched, %d manifest rows" % (a.manifest, matched, len(rows)))
    for k, (ok, bad) in stats.items():
        print("  %-32s equal %d, differ %d" % (k, ok, bad))
    for x in diffs[:80]:
        print("  DIFF " + x)


if __name__ == "__main__":
    try:
        main()
    except Bad as e:
        sys.exit("ERROR %s" % e)
