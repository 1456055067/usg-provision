# 0022: Applying Absolute Link and Junction Targets (OPEN-WIM-12)

- Status: Accepted (owner, 2026-10-28)
- Date: 2026-10-28
- Decider: project owner
- Refines: decision 0006 (WIM by black-box samples)
- Resolves: OPEN-WIM-12; review finding BOOT-001 (S11/S12 run)

## Context

Windows images contain absolute symbolic links and junctions. DISM rewrites
some of them when it captures an image (the header flag `RP_FIX`): it strips
the captured directory from the target and keeps the drive letter. The
product's DISM sample run R4 showed what DISM does on apply (OBS-049 to
OBS-052). For the entries it rewrote at capture, DISM re-bases both the
substitute name and the print name onto the apply root, whether that root
is another drive letter or a subdirectory, and recomputes their offsets and
lengths. Every other entry is copied byte for byte, including absolute
targets outside the captured tree, relative links, and images captured
without `RP_FIX`.

## Decision

1. The product applies link and junction targets the same way the samples
   show DISM does:
   - an entry that DISM rewrote at capture is re-based onto the apply root
     (OBS-050);
   - every other entry is written exactly as stored (OBS-051).
2. Only the combinations recorded in the samples are accepted. Any other
   combination is refused with a named reason (fail closed, decision 0006).
   That includes a tag other than symlink or mount point, an unexpected
   value at +92, a rewritten entry in a file without `RP_FIX`, or a target
   that does not parse under topic 24 §5.
3. What the +92 value means is a [reading] (OBS-052). The rule rests on the
   observed combination of the header flag, the +92 value and the stored
   name form, not on a documented field.
4. The owner's lab run (MT-2) confirms that junctions in a real Windows 11
   image resolve after the first boot.

## Consequences

- `usgp-image` and the Windows sink gain a re-base path for rewritten
  entries, built from topic 24's buffer layout. The product still never
  generates a target that is not in the image.
- Specs: `wim.md` §13 OPEN-WIM-12 becomes a [project rule] citing this
  decision.
