//! Writes the canonical tree manifest of a directory tree (plan M-20,
//! §10.2; S16 reference and the apply-fidelity comparison).
//!
//! Usage: `tree_manifest [--no-content] [--no-descend NAME]... <root>
//! [<out.tsv>]`
//!
//! Without an output path the manifest goes to standard output. Content
//! hashes are SHA-256 from `usgp-crypto` (FIPS provider). Windows only;
//! build with `--features manifest-tool`.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Testing and Evaluation)
//! - SPEC: specs/preinstall-env.md REQ-PE-017

#[cfg(windows)]
fn sha256_hex(path: &std::path::Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut h = usgp_crypto::Sha256Hasher::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(buf.get(..n).unwrap_or(&[]));
    }
    Ok(h.finish().to_hex())
}

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    use std::io::Write;
    use std::process::ExitCode;
    use usgp_winapi::manifest::{ManifestOptions, tree_rows};
    use usgp_winapi::manifest_text::render;

    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut opts = ManifestOptions::default();
    loop {
        match args.first().map(String::as_str) {
            Some("--no-content") => {
                opts.no_content = true;
                args.remove(0);
            }
            Some("--no-descend") if args.len() > 1 => {
                opts.no_descend.push(args.remove(1));
                args.remove(0);
            }
            _ => break,
        }
    }
    let (root, out) = match args.as_slice() {
        [root] => (root.clone(), None),
        [root, out] => (root.clone(), Some(out.clone())),
        _ => {
            eprintln!(
                "usage: tree_manifest [--no-content] [--no-descend NAME]... <root> [<out.tsv>]"
            );
            return ExitCode::from(2);
        }
    };
    if let Err(e) = usgp_crypto::fips_status() {
        eprintln!("tree_manifest: FIPS check failed: {e}");
        return ExitCode::from(1);
    }
    let rows = match tree_rows(std::path::Path::new(&root), &opts, &sha256_hex) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("tree_manifest: {e}");
            return ExitCode::from(1);
        }
    };
    let text = render(&rows);
    let written = match out {
        Some(p) => std::fs::write(p, text.as_bytes()),
        None => std::io::stdout().write_all(text.as_bytes()),
    };
    match written {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("tree_manifest: write failed: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("tree_manifest runs on Windows only");
    std::process::exit(2);
}
