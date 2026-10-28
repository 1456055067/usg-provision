# M3 analysis tool (WU-W3), kept as written for docs/formats/wim-observed.md.
#
# Only sources: specs/standards/wim.md sections 2, 3, 5, 6 and 7 (our
# summary of Microsoft's WIM paper, "WIM Metadata Resource" and the
# sections it relies on), the [observed] notes there (OBS-002, OBS-008,
# OBS-009, OBS-011, OBS-014, OBS-021), and xpr.py's decoder (written from
# specs/standards/wim-compression.md section 3) for compressed metadata.
# Written on the clean side; no third-party WIM, XPRESS, LZX or LZMS code,
# documentation or test data was read, recalled or compared against
# (decision 0006 item 2).
#
# Run: written before run R3 (plan M3 WU-W3, samples S13 to S17). The OBS
# records that use it cite the run ID and this file's commit. Samples are
# never committed (OPEN-PE-LIC); pass their paths as arguments.
#
# Walks the security block and the directory entries of each metadata
# resource and prints every field next to its offset, so that the records
# for OPEN-WIM-7 (plan M3 section 1.4, M-01 to M-17 and M-23) can cite
# bytes. Field order and sizes are wim.md section 6:
#   security block: total length (4), count (4), count x length (8), data;
#   root entry at the next 8-byte boundary after the security data;
#   entry: length (8), attributes (4), security index (4), children
#   offset (8), reserved (8), reserved (8), three times (8 each), hash
#   (20), reparse tag + reserved or hard-link group (8), stream count (2),
#   short name length (2), name length (2), name; fixed part 98 bytes;
#   stream entry: length (8), reserved (8), hash (20), name length (2),
#   name; a directory's list ends with a 64-bit zero.
# Where wim.md is silent (alignment, short-name placement, what follows
# the name) nothing is assumed: the bytes are printed as hex, the
# alignment is a parameter (--align, default 8, the root's stated
# alignment) and every padding byte skipped is shown. Children are walked
# from the children offset whenever it is non-zero, whatever the
# attributes say; the attribute value 0x400 is used only to label the
# 8-byte union, as wim.md section 6 states.
#
# Every offset and length read from the file is checked before use;
# limits stop runaway input. A problem prints "ERROR" and stops that list.
#
# Usage: python3 -I dentry.py [--xpr <path to xpr.py>] [--image K]
#                             [--align N] [--root-offset N] [--hex]
#                             [--max-entries N] <file.wim>
import argparse
import hashlib
import re
import sys

FIXED = 98
STREAM_FIXED = 38
MAX_FILE = 1 << 30
MAX_META = 256 << 20
MAX_DEPTH = 1024
TAIL_SHOWN = 256
SD_SHOWN = 512
CHUNK = 32768


class Bad(Exception):
    pass


def u16(b, o):
    if o < 0 or o + 2 > len(b):
        raise Bad("u16 at %d past end %d" % (o, len(b)))
    return int.from_bytes(b[o:o + 2], "little")


def u32(b, o):
    if o < 0 or o + 4 > len(b):
        raise Bad("u32 at %d past end %d" % (o, len(b)))
    return int.from_bytes(b[o:o + 4], "little")


def u64(b, o):
    if o < 0 or o + 8 > len(b):
        raise Bad("u64 at %d past end %d" % (o, len(b)))
    return int.from_bytes(b[o:o + 8], "little")


def i32(b, o):
    if o < 0 or o + 4 > len(b):
        raise Bad("i32 at %d past end %d" % (o, len(b)))
    return int.from_bytes(b[o:o + 4], "little", signed=True)


def hx(b, o, n):
    return b[o:o + n].hex(" ")


def rh(b, o):
    # wim.md section 3: 7-byte stored size, flag byte, offset, original size.
    return (int.from_bytes(b[o:o + 7], "little"), b[o + 7],
            int.from_bytes(b[o + 8:o + 16], "little"),
            int.from_bytes(b[o + 16:o + 24], "little"))


def load_xpr(path):
    # As metamap.py: the decoder functions, without xpr.py's command-line part.
    with open(path, encoding="utf-8") as f:
        src = f.read().split("verbose='-v'")[0]
    ns = {}
    exec(src, ns)
    return ns


def utf16(b):
    try:
        return b.decode("utf-16-le")
    except UnicodeDecodeError as e:
        return "<not UTF-16LE: %s>" % e


def resource_bytes(d, S, F, O, U, xpr):
    """Uncompressed bytes of one resource (wim.md section 4, OBS-011)."""
    if O > len(d) or S > len(d) - O:
        raise Bad("resource [%d, +%d) outside the file" % (O, S))
    if U > MAX_META:
        raise Bad("original size %d over the %d cap" % (U, MAX_META))
    raw = d[O:O + S]
    if not F & 0x04:
        if S != U:
            raise Bad("uncompressed resource with stored %d != original %d" % (S, U))
        return raw
    if xpr is None:
        raise Bad("compressed metadata; pass --xpr <path to xpr.py>")
    if U > 0xFFFFFFFF:
        raise Bad("chunk-table width over 4 GiB is OPEN-WIM-10; not read")
    n = (U + CHUNK - 1) // CHUNK
    tab = n - 1
    if tab * 4 > S:
        raise Bad("chunk table larger than the resource")
    starts = [0] + [u32(raw, k * 4) for k in range(tab)]
    data = raw[tab * 4:]
    ends = starts[1:] + [len(data)]
    out = bytearray()
    for c in range(n):
        exp = CHUNK if c < n - 1 else U - CHUNK * (n - 1)
        if not starts[c] < ends[c] <= len(data):
            raise Bad("chunk %d bounds %d..%d invalid" % (c, starts[c], ends[c]))
        size = ends[c] - starts[c]
        if size == exp:
            # OPEN-WIM-5, chunk level: not observed; not guessed.
            raise Bad("chunk %d stored size equals its expanded size %d "
                      "(OPEN-WIM-5 chunk level); not decoded" % (c, exp))
        o, _ = xpr["decode"](data[starts[c]:ends[c]], exp, False)
        out += o
    return bytes(out)


class Walker:
    def __init__(self, m, args, lookup):
        self.m = m
        self.a = args
        self.lookup = lookup
        self.entries = 0
        self.streams = 0
        self.with_children = 0
        self.pads_nonzero = 0
        self.len_mod = {4: 0, 8: 0}
        self.groups = {}
        self.seen_lists = set()
        self.sec_count = 0
        self.errors = 0

    def pad(self, pos, what):
        a = self.a.align
        p = (pos + a - 1) // a * a
        if p != pos:
            gap = self.m[pos:p]
            nz = any(gap)
            if nz:
                self.pads_nonzero += 1
            print("    pad %d byte(s) @%d before %s: %s%s"
                  % (p - pos, pos, what, gap.hex(" "), "  NON-ZERO" if nz else ""))
        return p

    def hash_note(self, h):
        if not any(h):
            return "zero hash"
        e = self.lookup.get(h)
        if e is None:
            return "no lookup entry"
        return "lookup stored=%d flags=0x%02x original=%d" % (e[0], e[1], e[3])

    def entry(self, o, path, depth):
        """Prints one entry at o; returns (length, children offset, name)."""
        m = self.m
        length = u64(m, o)
        if length == 0:
            return 0, 0, None
        if o + FIXED > len(m):
            raise Bad("entry @%d: fixed part past end" % o)
        if length < FIXED or length > len(m) - o:
            raise Bad("entry @%d: length %d out of range" % (o, length))
        attr = u32(m, o + 8)
        sec = i32(m, o + 12)
        sub = u64(m, o + 16)
        r1 = u64(m, o + 24)
        r2 = u64(m, o + 32)
        ct, at, wt = u64(m, o + 40), u64(m, o + 48), u64(m, o + 56)
        h = m[o + 64:o + 84]
        un = m[o + 84:o + 92]
        nstr = u16(m, o + 92)
        slen = u16(m, o + 94)
        nlen = u16(m, o + 96)
        if 98 + nlen > length:
            raise Bad("entry @%d: name length %d beyond entry length %d" % (o, nlen, length))
        if nlen % 2:
            raise Bad("entry @%d: odd name length %d" % (o, nlen))
        name = utf16(m[o + 98:o + 98 + nlen])
        full = name if path is None else (path + "\\" + name)
        self.entries += 1
        for k in self.len_mod:
            if length % k:
                self.len_mod[k] += 1
        if sub:
            self.with_children += 1
        print("E @%d depth=%d path=%r" % (o, depth, full))
        print("    length=%d attributes=0x%08x security=%d children=%d reserved1=%d reserved2=%d"
              % (length, attr, sec, sub, r1, r2))
        print("    raw @%d..%d: %s" % (o, o + 40, hx(m, o, 40)))
        print("    times @%d: %d %d %d  (%s)" % (o + 40, ct, at, wt, hx(m, o + 40, 24)))
        print("    hash @%d: %s  [%s]" % (o + 64, h.hex(), self.hash_note(h)))
        if attr & 0x400:
            print("    union @%d (0x400 set: reparse tag, reserved): %s  u32 %d u32 %d"
                  % (o + 84, un.hex(" "), u32(un, 0), u32(un, 4)))
        else:
            g = int.from_bytes(un, "little")
            print("    union @%d (0x400 clear: hard-link group): %s  u64 %d" % (o + 84, un.hex(" "), g))
            if g:
                self.groups.setdefault(g, []).append(full)
        print("    streams=%d short_name_length=%d name_length=%d name=%r" % (nstr, slen, nlen, name))
        if sec != -1 and not 0 <= sec < self.sec_count:
            print("    NOTE security index %d outside 0..%d" % (sec, self.sec_count - 1))
        t0 = o + 98 + nlen
        tail = m[t0:o + length]
        shown = tail[:TAIL_SHOWN]
        print("    after name @%d (%d bytes to entry end): %s%s"
              % (t0, len(tail), shown.hex(" "), " ..." if len(tail) > len(shown) else ""))
        if slen and len(tail) >= 2 + slen:
            # [reading] for the record to confirm or refute: the short
            # name after the long name's 2-byte terminator (M-05).
            print("    candidate short name (reading: after a 2-byte terminator): %r"
                  % utf16(tail[2:2 + slen]))
        pos = o + length
        for k in range(nstr):
            pos = self.pad(pos, "stream %d" % k)
            if pos + STREAM_FIXED > len(m):
                raise Bad("stream @%d: fixed part past end" % pos)
            sl = u64(m, pos)
            if sl < STREAM_FIXED or sl > len(m) - pos:
                raise Bad("stream @%d: length %d out of range" % (pos, sl))
            sh = m[pos + 16:pos + 36]
            snl = u16(m, pos + 36)
            if STREAM_FIXED + snl > sl or snl % 2:
                raise Bad("stream @%d: name length %d invalid" % (pos, snl))
            sname = utf16(m[pos + 38:pos + 38 + snl])
            self.streams += 1
            print("  S @%d length=%d reserved=%d hash=%s [%s] name_length=%d name=%r"
                  % (pos, sl, u64(m, pos + 8), sh.hex(), self.hash_note(sh), snl, sname))
            print("    raw fixed: %s" % hx(m, pos, STREAM_FIXED))
            st = m[pos + 38 + snl:pos + sl]
            print("    after name (%d bytes): %s" % (len(st), st[:TAIL_SHOWN].hex(" ")))
            pos += sl
        return pos - o, sub, full

    def walk_list(self, off, path, depth):
        if depth > MAX_DEPTH:
            raise Bad("depth over %d" % MAX_DEPTH)
        if off in self.seen_lists:
            print("ERROR list @%d already walked (cycle or shared); skipped" % off)
            self.errors += 1
            return
        self.seen_lists.add(off)
        print("L @%d children of %r" % (off, path))
        pos = off
        pending = []
        while True:
            if self.entries >= self.a.max_entries:
                raise Bad("entry limit %d reached" % self.a.max_entries)
            pos = self.pad(pos, "entry")
            if pos + 8 > len(self.m):
                raise Bad("list @%d: end marker past end" % off)
            used, sub, full = self.entry(pos, path, depth)
            if used == 0:
                print("  END @%d: %s" % (pos, hx(self.m, pos, 8)))
                break
            if sub:
                pending.append((sub, full))
            pos += used
        for sub, full in pending:
            try:
                self.walk_list(sub, full, depth + 1)
            except Bad as e:
                print("ERROR %s" % e)
                self.errors += 1


def security(m):
    total, count = u32(m, 0), u32(m, 4)
    print("security @0: total-length field %d (%s); count field %d (%s)"
          % (total, hx(m, 0, 4), count, hx(m, 4, 4)))
    if 8 + 8 * count > len(m):
        raise Bad("security: %d lengths do not fit" % count)
    lens = [u64(m, 8 + 8 * k) for k in range(count)]
    pos = 8 + 8 * count
    digests = {}
    for k, n in enumerate(lens):
        if n > len(m) - pos:
            raise Bad("security: descriptor %d length %d past end" % (k, n))
        sd = m[pos:pos + n]
        dg = hashlib.sha256(sd).hexdigest()
        digests.setdefault(dg, []).append(k)
        print("  SD[%d] @%d length=%d sha256=%s" % (k, pos, n, dg))
        print("    %s%s" % (sd[:SD_SHOWN].hex(" "), " ..." if n > SD_SHOWN else ""))
        pos += n
    dup = {d: ks for d, ks in digests.items() if len(ks) > 1}
    print("  computed end 8 + 8 * count + sum(lengths) = %d; next 8-byte boundary %d; "
          "total-length field %d" % (pos, (pos + 7) // 8 * 8, total))
    print("  identical descriptors: %s" % (dup if dup else "none"))
    gap = m[pos:(pos + 7) // 8 * 8]
    print("  bytes from computed end to the boundary: %s" % (gap.hex(" ") or "none"))
    return count, (pos + 7) // 8 * 8


def xml_counts(d, k):
    s, _, o, _ = rh(d, 72)
    if o > len(d) or s > len(d) - o or s < 2:
        return None
    x = d[o:o + s]
    if x[:2] != b"\xff\xfe":
        return None
    t = x[2:2 + (len(x) - 2) // 2 * 2].decode("utf-16-le", "replace")
    m = re.search(r'<IMAGE INDEX="%d">(.*?)</IMAGE>' % k, t, re.S)
    if not m:
        return None
    got = {}
    for tag in ("DIRCOUNT", "FILECOUNT", "TOTALBYTES", "HARDLINKBYTES"):
        v = re.search(r"<%s>([^<]*)</%s>" % (tag, tag), m.group(1))
        got[tag] = v.group(1) if v else "(absent)"
    return got


def main():
    p = argparse.ArgumentParser(description="Walk WIM metadata (wim.md section 6).")
    p.add_argument("wim")
    p.add_argument("--xpr", help="path to xpr.py (needed for compressed metadata)")
    p.add_argument("--image", type=int, default=0, help="image index (default: all)")
    p.add_argument("--align", type=int, choices=(1, 2, 4, 8), default=8)
    p.add_argument("--root-offset", type=int, default=-1)
    p.add_argument("--max-entries", type=int, default=200000)
    a = p.parse_args()
    with open(a.wim, "rb") as f:
        d = f.read(MAX_FILE + 1)
    if len(d) > MAX_FILE:
        sys.exit("file over %d bytes; not read" % MAX_FILE)
    if len(d) < 208 or d[:5] != b"MSWIM":
        sys.exit("not a WIM header (wim.md section 2)")
    xpr = load_xpr(a.xpr) if a.xpr else None
    S, F, O, U = rh(d, 48)
    if O > len(d) or S > len(d) - O or S % 50:
        sys.exit("lookup table [%d, +%d) unusable" % (O, S))
    t = d[O:O + S]
    lookup, meta = {}, []
    for i in range(S // 50):
        e = t[i * 50:(i + 1) * 50]
        r = rh(e, 0)
        h = bytes(e[30:50])
        if r[1] & 0x02:
            meta.append((i, r, h))
        else:
            lookup.setdefault(h, r)
    print("== %s length %d; %d lookup entries, %d metadata (lookup order = index, OBS-009/021)"
          % (a.wim, len(d), S // 50, len(meta)))
    for k, (i, r, h) in enumerate(meta, start=1):
        if a.image and k != a.image:
            continue
        print("\n=== image %d: lookup [%d] stored=%d flags=0x%02x offset=%d original=%d"
              % (k, i, r[0], r[1], r[2], r[3]))
        try:
            m = resource_bytes(d, *r, xpr)
        except Bad as e:
            print("ERROR %s" % e)
            continue
        print("metadata %d bytes; SHA-1 %s lookup hash" % (
            len(m), "matches" if hashlib.sha1(m).digest() == h else "DIFFERS FROM"))
        w = Walker(m, a, lookup)
        try:
            w.sec_count, root = security(m)
            if a.root_offset >= 0:
                print("root offset overridden: %d (computed %d)" % (a.root_offset, root))
                root = a.root_offset
            print("root entry @%d (alignment used: %d)" % (root, a.align))
            used, sub, full = w.entry(root, None, 0)
            if used and sub:
                w.walk_list(sub, full, 1)
            if used:
                print("after root entry @%d: %s" % (root + used, hx(m, root + used, 16)))
        except Bad as e:
            print("ERROR %s" % e)
            w.errors += 1
        groups = {g: n for g, n in w.groups.items() if len(n) > 1}
        print("\nsummary image %d: entries %d (root included), with children offset %d, "
              "without %d; stream entries %d; lengths not a multiple of 4: %d, of 8: %d; "
              "non-zero pads %d; errors %d"
              % (k, w.entries, w.with_children, w.entries - w.with_children, w.streams,
                 w.len_mod[4], w.len_mod[8], w.pads_nonzero, w.errors))
        print("hard-link groups with more than one name: %s" % (groups if groups else "none"))
        singles = sum(1 for n in w.groups.values() if len(n) == 1)
        print("non-zero group values used once: %d" % singles)
        print("XML for index %d: %s" % (k, xml_counts(d, k)))


if __name__ == "__main__":
    main()
