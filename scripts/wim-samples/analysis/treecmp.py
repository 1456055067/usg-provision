# R3 analysis tool (M3 WU-W3), kept as run for docs/formats/wim-observed.md.
#
# Only sources: the tree manifests Build-Samples.ps1 writes (its
# Save-TreeManifest; column contract in scripts/wim-samples/README.md),
# from the R3 artifacts. No WIM layout knowledge is used. Written on the
# clean side; no third-party WIM code, documentation or test data was read,
# recalled or compared against (decision 0006 item 2).
#
# Run: R3 = wim-samples workflow run 40754869824, attempt 1, commit
# 27f7237d99c67a9cc575268398dd4193ae1fbccf. The manifests are text
# artifacts of that run; pass their paths as arguments.
#
# Compares two tree manifests column by column for every path in both
# (M-20: DISM's apply of S13, S16.manifest.tsv, against its source,
# tree-meta.manifest.tsv). Prints per-column equal/differ counts and every
# difference (capped). --strip-links removes a leading path prefix from
# the hard-links column of the first manifest (the source volume held the
# tree under "\tree-meta"; S16 applied it to a volume root).
# Usage: python3 -I treecmp.py [--strip-links P] <source.tsv> <applied.tsv>
import argparse

CAP = 200


def load(p):
    with open(p, encoding="utf-8") as f:
        head = f.readline().rstrip("\n").split("\t")
        rows = {}
        for line in f:
            c = line.rstrip("\n").split("\t")
            if len(c) != len(head):
                raise SystemExit("%s: row with %d fields" % (p, len(c)))
            rows[c[0]] = dict(zip(head, c))
    return head, rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("source")
    ap.add_argument("applied")
    ap.add_argument("--strip-links", default="")
    a = ap.parse_args()
    head, src = load(a.source)
    head2, dst = load(a.applied)
    if head != head2:
        raise SystemExit("headers differ")
    only_src = sorted(set(src) - set(dst))
    only_dst = sorted(set(dst) - set(src))
    print("paths: source %d, applied %d, both %d" % (len(src), len(dst), len(set(src) & set(dst))))
    print("only in source: %s" % (only_src[:20] or "none"))
    print("only in applied: %s" % (only_dst[:20] or "none"))
    stats = {c: [0, 0] for c in head[1:]}
    diffs = []
    for p in sorted(set(src) & set(dst)):
        s, d = src[p], dst[p]
        for c in head[1:]:
            x, y = s[c], d[c]
            if c == "hard-links" and a.strip_links and x != "-":
                x = "|".join(v[len(a.strip_links):] if v.startswith(a.strip_links) else v
                             for v in x.split("|"))
            ok = x == y
            stats[c][0 if ok else 1] += 1
            if not ok:
                diffs.append("%s [%s]\n      source  %s\n      applied %s" % (p, c, x, y))
    for c, (ok, bad) in stats.items():
        print("  %-12s equal %5d  differ %5d" % (c, ok, bad))
    for x in diffs[:CAP]:
        print("  DIFF " + x)
    if len(diffs) > CAP:
        print("  (%d more differences)" % (len(diffs) - CAP))


if __name__ == "__main__":
    main()
