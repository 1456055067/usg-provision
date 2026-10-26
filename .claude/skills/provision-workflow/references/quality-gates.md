# Quality Gates

Scope to touched crates (`-p <crate>`) while iterating; run the workspace form
once before the final gate. Once a `Makefile` exists, prefer its targets and
update this table to match.

| Gate | Iterating | Final | Required |
|------|-----------|-------|----------|
| Format | `cargo fmt --all` | `cargo fmt --all --check` | Yes |
| Lint | `cargo clippy -p <crate> --all-targets -- -D warnings` | `cargo clippy --workspace --all-targets -- -D warnings` | Yes |
| Unit tests | `cargo test -p <crate> --lib` | `cargo test --workspace` | Yes |
| Doc tests | `cargo test -p <crate> --doc` | `cargo test --workspace --doc` | When public API changed |
| Integration | `cargo test -p <crate> --test <name>` | `cargo test --workspace --tests` | When service behaviour changed |
| Pure Rust | `scripts/check-pure-rust.sh` (or `cargo tree -p <crate> -e normal,build --prune usgp-crypto \| grep -E -- '-sys \|cc v\|bindgen'`, must print nothing) | `cargo tree -i aws-lc-fips-sys -e normal,build` shows only `usgp-crypto` as a direct dependent, and no other `-sys` crate appears in the workspace tree (decision 0001) | Yes when deps changed |
| Supply chain | — | `cargo deny check` and `cargo audit` | When `Cargo.toml`/`Cargo.lock` changed |
| Fuzz smoke | `cargo fuzz run <target> -- -max_total_time=60` | each touched target, 60 s | When a parser changed |
| Boot smoke | QEMU + OVMF PXE/HTTP boot against a local relay (see `docs/TESTING.md` once written) | same | When boot path changed; NOT RUN if QEMU/OVMF absent |
| Clean-room names | `rg -i tanium --glob '!specs/README.md' --glob '!cleanroom/**' --glob '!CLAUDE.md' --glob '!.claude/**'` (must print nothing) | same | Yes |
| Spec traceability | every REQ ID in `brief.md` appears in `docs/compliance/SPEC_TRACEABILITY.md` with code + test | same | Yes for feature work |
| Markdown | — | `npx markdownlint-cli "docs/**/*.md" "specs/**/*.md"` | When docs/specs changed |

## Rules

- Record every command with its exit status and the last relevant lines of
  output in `qa-report.md`. "Tests pass" without the command is not evidence.
- Missing environment (QEMU, OVMF, a Windows image, root for raw-disk tests):
  mark the gate **NOT RUN** with the reason, never PASS.
- Tests that write disks use loopback files or temp images only, never a real
  block device.
- No new `#[allow(clippy::...)]`, `#[ignore]`, or `unwrap()` on untrusted input
  without a justification comment and a finding entry.
- Run final workspace gates and fuzzing in the background.
