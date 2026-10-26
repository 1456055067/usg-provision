# 0005: Scope of the Clean-Room Name Gates

- Status: Accepted (owner, 2026-10-26)
- Date: 2026-10-26
- Decider: project owner
- Drafted by: rust-coder (clean side), to resolve clean-room findings
  CR-302 and CR-303 (M1 code pass)
- Basis: CLAUDE.md clean-room rule 5; clean-room protocol

## Context

`scripts/check-names.sh` searches the tree for the vendor product name
(CLAUDE.md clean-room rule 5) in path names and in file contents, binary
files included. It skips a short list of root-anchored locations.

In M1 the gate failed on build output of the `testing/` workspaces. A
third-party crate's compiled metadata names the 64-bit processor family of
RFC 4578 architecture type 2, and that family's full name contains the
gate's pattern. The hit was a false positive. It was fixed by sending the
`testing/` build output to the root `target/` directory
(`testing/*/.cargo/config.toml`), which the gate skips as build output.

Two risks remain:

1. A future contributor may fix the next false positive by adding an
   exclusion (for example `testing/*/target/` or `fuzz/target/`). Every
   exclusion is a place the name could hide.
2. The root `target/` is not scanned, so the files that leave the build
   host (release binaries, UEFI payloads, boot smoke evidence) were never
   checked by a script.

## Decision

1. **Exclusions are fixed.** The source-tree gate skips exactly these
   root-anchored paths and nothing else:

   <!-- names-gate-exclusions:begin -->

   ```text
   /.claude
   /.git
   /CLAUDE.md
   /cleanroom
   /specs/README.md
   /target
   ```

   <!-- names-gate-exclusions:end -->

   `/CLAUDE.md`, `/.claude/`, `/specs/README.md` and `/cleanroom/` are
   where CLAUDE.md rule 5 and the clean-room protocol allow the name.
   `/target/` is root build output and `/.git/` is version-control
   metadata. `scripts/test-check-names.sh` checks that this list, the
   list in its own source, and the gate's `find` expressions are the same.
   A change to one without the others fails the gate's own tests.
2. **Nested build output is scanned on purpose.** `fuzz/target/`,
   `testing/*/target/` and any other `target/` below the root are checked
   like source. Separate workspaces under `testing/` build into the root
   `target/` (`target/testing/<name>/`) through their
   `.cargo/config.toml`.
3. **False positives are fixed by moving output or renaming, never by
   excluding paths.** Move build output under the root `target/`, rename
   our own identifier, or change what goes into the artifact. Do not add
   an exclusion, a per-file allowance or a pattern exception.
4. **Our own text never spells the processor family's full name.** Write
   "IA-64" or "ia64" (CONTRIBUTING.md, clean-room rules).
5. **Shipped artifacts are scanned separately, with no exclusions.**
   `scripts/check-artifact-names.sh` scans exactly the release `usgp-relay`
   and `usgp-cli` binaries, both staged `.efi` payloads, and the boot smoke
   evidence directory `target/boot-smoke/` (when present). It fails on any
   hit and fails closed if a required artifact is missing.
   `scripts/gates.sh` runs it after the release build. Re-including all of
   `target/` is not the fix, because intermediate build output holds
   third-party metadata that never ships.

## Consequences

- A third-party crate whose metadata contains the pattern can fail the
  gate again if its output lands outside the root `target/`. The fix is
  to move that output.
- If a third-party string reaches a shipped artifact, the artifact gate
  fails. The fix is to change the build (for example, strip the symbol or
  section), not to exclude the file. If that is not possible, the owner
  decides in a new decision record.
- CI does not yet run `scripts/check-artifact-names.sh`. The release
  engineer wires it into the release and boot smoke jobs, after the
  artifacts are built and before upload.
