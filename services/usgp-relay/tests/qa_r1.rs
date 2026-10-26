//! QA re-verify round 1 for milestone M1 (qa-engineer, SA-11 / CA-2
//! evidence): tests for behaviour added in fix round 1 that the coders'
//! own tests did not pin down.
//!
//! - trusted files (NIST-002 / SEC-005): symlinked manifest and
//!   suppression file refused; suppression reload refuses a symlink swap,
//!   a group-writable parent or an untrusted owner and keeps the previous
//!   list; root-owned files accepted under the root-only policy;
//! - `--admin-uid` process contract: another uid's files refused, option
//!   order and repetition are usage errors;
//! - `tftp.handshake_timeout_ms` must not exceed `tftp.max_transfer_secs`;
//! - NIST-003: `--check-config` refusals are audited with the field;
//! - SEC-006: check results are ordered by start, whatever order they
//!   finish in (randomised interleavings against a model).
//!
//! All fixtures are generated at test time in temp directories.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11, CA-2, CM-5, SI-7, AU-2, AU-12, SC-5
//! - SPEC: specs/boot-network.md#REQ-BOOT-050, -052, -053

#[cfg(test)]
pub mod common;

#[cfg(test)]
mod qa_r1 {
    use std::path::Path;
    use std::process::{Command, Output};

    use usgp_common::config::{ConfigError, TrustPolicy, TrustRule, read_trusted};
    use usgp_relay::config::{ConfigLoadError, load};
    use usgp_relay::content::ContentStore;
    use usgp_relay::state::{FileStatus, RelayState};
    use usgp_relay::suppress::{ReloadOutcome, Suppression, SuppressionError};

    use crate::common::{
        PROGRAM, Scratch, admin_uid, bytes, config, set_mode, trust, write_config_toml,
    };

    const SUPP_ONE: &str = "schema_version = 1\n[[device]]\nmac = \"52:54:00:12:34:56\"\n";

    fn mac() -> usgp_dhcp::MacAddr {
        "52:54:00:12:34:56".parse().unwrap()
    }

    fn relay(args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_usgp-relay"))
            .args(args)
            .output()
            .expect("spawn usgp-relay")
    }

    fn text(b: &[u8]) -> String {
        String::from_utf8_lossy(b).into_owned()
    }

    fn write_supp(path: &Path, body: &str) {
        std::fs::write(path, body).unwrap();
        set_mode(path, 0o644);
    }

    // -----------------------------------------------------------------
    // Trusted files
    // -----------------------------------------------------------------

    /// A manifest reached through a symlink is refused by config load and
    /// by the content store (final component never followed).
    #[test]
    fn symlinked_manifest_refused() {
        let s = Scratch::new("qa-r1-mlink");
        s.publish(&[(PROGRAM, b"payload")]);
        let real = s.dir.join("real-manifest.toml");
        std::fs::rename(s.manifest_path(), &real).unwrap();
        std::os::unix::fs::symlink(&real, s.manifest_path()).unwrap();
        let p = write_config_toml(&s, "");
        let e = load(&p, trust()).unwrap_err();
        assert!(
            matches!(e, ConfigLoadError::File(ConfigError::Symlink { .. })),
            "{e:?}"
        );
        let c = config(&s);
        let e = ContentStore::load(
            &c.boot.manifest,
            &c.boot.root,
            &c.boot.uefi_x64_program,
            c.tftp.max_file_size,
            1,
            &c.trust,
        )
        .unwrap_err();
        assert!(
            e.to_string().to_lowercase().contains("symbolic link")
                || e.to_string().to_lowercase().contains("symlink"),
            "{e}"
        );
    }

    /// The suppression file: symlink refused at start-up; at reload a
    /// symlink swap, a group-writable parent directory and an untrusted
    /// owner are each refused and the previous list stays in force.
    #[test]
    fn suppression_file_trust_rules_at_start_and_reload() {
        let s = Scratch::new("qa-r1-supp");
        let path = s.dir.join("suppress.toml");
        let other = s.dir.join("other.toml");
        write_supp(&other, "schema_version = 1\n");

        // Start-up through a symlink: refused.
        std::os::unix::fs::symlink(&other, &path).unwrap();
        let e = Suppression::load_initial(&path, trust()).unwrap_err();
        assert!(
            matches!(e, SuppressionError::File(ConfigError::Symlink { .. })),
            "{e:?}"
        );
        std::fs::remove_file(&path).unwrap();

        write_supp(&path, SUPP_ONE);
        let h = Suppression::load_initial(&path, trust()).unwrap();
        assert!(h.current().contains(mac(), None));

        // Swapped for a symlink to an empty list: refused, list kept.
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&other, &path).unwrap();
        assert_eq!(h.reload(), ReloadOutcome::Rejected);
        assert!(h.current().contains(mac(), None));
        std::fs::remove_file(&path).unwrap();

        // Group-writable parent directory: refused, list kept.
        write_supp(&path, "schema_version = 1\n");
        set_mode(&s.dir, 0o775);
        assert_eq!(h.reload(), ReloadOutcome::Rejected);
        assert!(h.current().contains(mac(), None));
        // Sticky bit makes a writable directory acceptable.
        set_mode(&s.dir, 0o1777);
        assert_eq!(h.reload(), ReloadOutcome::Loaded);
        assert!(!h.current().contains(mac(), None));
        set_mode(&s.dir, 0o755);

        // Untrusted owner (policy naming another uid): refused at start-up.
        if admin_uid() != 0 {
            let p = TrustPolicy::with_admin(admin_uid().wrapping_add(1));
            let e = Suppression::load_initial(&path, p).unwrap_err();
            assert!(
                matches!(
                    e,
                    SuppressionError::File(ConfigError::Untrusted {
                        rule: TrustRule::Owner,
                        ..
                    })
                ),
                "{e:?}"
            );
            // And at reload (the file is polled under a policy that does
            // not trust its owner), keeping the previous list.
            let h = Suppression::with_list(
                Some(path.clone()),
                usgp_relay::suppress::SuppressionList::from_ids(&[mac()], &[]).unwrap(),
            )
            .with_trust(TrustPolicy::with_admin(admin_uid().wrapping_add(1)));
            write_supp(&path, "schema_version = 1\n");
            assert_eq!(h.reload(), ReloadOutcome::Rejected);
            assert!(h.current().contains(mac(), None));
        }
    }

    /// Root-owned files are trusted under the root-only policy (the
    /// default with no `--admin-uid`). Uses a root-owned, non-writable
    /// system file when one exists; skipped otherwise.
    #[test]
    fn root_owned_file_trusted_by_root_only_policy() {
        use std::os::unix::fs::MetadataExt;
        let Ok(real) = std::fs::canonicalize("/etc/hosts") else {
            return;
        };
        let Ok(m) = std::fs::symlink_metadata(&real) else {
            return;
        };
        if m.uid() != 0 || m.mode() & 0o022 != 0 || !m.is_file() {
            return;
        }
        read_trusted(&real, 1 << 20, &TrustPolicy::root_only()).unwrap();
        if admin_uid() != 0 {
            // The admin-uid policy still trusts root.
            read_trusted(&real, 1 << 20, &trust()).unwrap();
        }
    }

    // -----------------------------------------------------------------
    // Configuration rules added in round 1
    // -----------------------------------------------------------------

    #[test]
    fn handshake_timeout_must_not_exceed_max_transfer() {
        let s = Scratch::new("qa-r1-hs");
        s.publish(&[(PROGRAM, b"payload")]);
        let p = write_config_toml(
            &s,
            "[tftp]\nhandshake_timeout_ms = 10001\nmax_transfer_secs = 10\n",
        );
        let e = load(&p, trust()).unwrap_err();
        assert_eq!(e.field(), "tftp.handshake_timeout_ms", "{e:?}");
        let p = write_config_toml(
            &s,
            "[tftp]\nhandshake_timeout_ms = 10000\nmax_transfer_secs = 10\n",
        );
        let c = load(&p, trust()).unwrap().config;
        assert_eq!(
            c.tftp_listener_config().handshake_timeout,
            std::time::Duration::from_secs(10)
        );
    }

    // -----------------------------------------------------------------
    // --admin-uid process contract and NIST-003 audit of refusals
    // -----------------------------------------------------------------

    #[test]
    fn admin_uid_of_another_user_refuses_and_audits() {
        if admin_uid() == 0 {
            return;
        }
        let s = Scratch::new("qa-r1-otheruid");
        s.publish(&[(PROGRAM, &bytes(10, 1))]);
        let p = write_config_toml(&s, "");
        let other = admin_uid().wrapping_add(1).to_string();
        for mode in ["--check-config", "--config"] {
            let out = relay(&[mode, p.to_str().unwrap(), "--admin-uid", &other]);
            assert_eq!(out.status.code(), Some(78), "{mode}: {}", text(&out.stderr));
            assert!(
                text(&out.stderr).contains("not trusted"),
                "{}",
                text(&out.stderr)
            );
            let stdout = text(&out.stdout);
            let line = stdout
                .lines()
                .find(|l| l.contains("relay.config.rejected"))
                .unwrap_or_else(|| panic!("{mode}: no relay.config.rejected in {stdout}"));
            assert!(line.contains("\"outcome\":\"refused\""), "{line}");
        }
        // Root is always trusted, but uid 0 does not own these files.
        let out = relay(&["--check-config", p.to_str().unwrap(), "--admin-uid", "0"]);
        assert_eq!(out.status.code(), Some(78));
    }

    #[test]
    fn admin_uid_position_and_repetition_are_usage_errors() {
        let uid = admin_uid().to_string();
        for args in [
            vec!["--admin-uid", uid.as_str(), "--config", "/x.toml"],
            vec!["--admin-uid", uid.as_str(), "--check-config", "/x.toml"],
            vec![
                "--config",
                "/x.toml",
                "--admin-uid",
                uid.as_str(),
                "--admin-uid",
                uid.as_str(),
            ],
            vec!["--check-config", "/x.toml", "--admin-uid"],
            vec!["--check-config", "/x.toml", "--admin-uid", "-1"],
        ] {
            let out = relay(&args);
            assert_eq!(
                out.status.code(),
                Some(2),
                "{args:?}: {}",
                text(&out.stderr)
            );
            assert!(text(&out.stderr).contains("usage:"), "{args:?}");
        }
    }

    /// NIST-003: `--check-config` audits why a configuration was refused,
    /// naming the field, and a symlinked config is refused (78).
    #[test]
    fn check_config_refusals_audited_with_field() {
        let s = Scratch::new("qa-r1-ccaudit");
        s.publish(&[(PROGRAM, &bytes(10, 1))]);
        let uid = admin_uid().to_string();
        for (extra, field) in [
            ("[tftp]\nmax_block_size = 7\n", "tftp.max_block_size"),
            (
                "[tftp]\nhandshake_timeout_ms = 20000\nmax_transfer_secs = 10\n",
                "tftp.handshake_timeout_ms",
            ),
            (
                "[limits]\ndhcp_relayed_global_per_sec = 0\n",
                "limits.dhcp_relayed_global_per_sec",
            ),
            (
                "[limits]\ntftp_rrq_global_burst = 0\n",
                "limits.tftp_rrq_global_burst",
            ),
        ] {
            let p = write_config_toml(&s, extra);
            let out = relay(&["--check-config", p.to_str().unwrap(), "--admin-uid", &uid]);
            assert_eq!(
                out.status.code(),
                Some(78),
                "{extra}: {}",
                text(&out.stderr)
            );
            let stdout = text(&out.stdout);
            let line = stdout
                .lines()
                .find(|l| l.contains("relay.config.rejected"))
                .unwrap_or_else(|| panic!("{extra}: no event in {stdout}"));
            assert!(line.contains(field), "{field}: {line}");
            assert!(line.contains("\"outcome\":\"refused\""), "{line}");
        }
        let p = write_config_toml(&s, "");
        let link = s.dir.join("link.toml");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        let out = relay(&[
            "--check-config",
            link.to_str().unwrap(),
            "--admin-uid",
            &uid,
        ]);
        assert_eq!(out.status.code(), Some(78), "{}", text(&out.stderr));
        assert!(text(&out.stdout).contains("relay.config.rejected"));
    }

    // -----------------------------------------------------------------
    // SEC-006: results ordered by when the check started
    // -----------------------------------------------------------------

    /// Random interleavings of overlapping checks of one file: every
    /// result is applied if and only if no later-started check has been
    /// recorded, and the state always reflects the latest-started recorded
    /// result. Model-based; 2000 schedules.
    #[test]
    fn check_results_ordered_by_start_under_random_interleaving() {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let statuses = [
            FileStatus::Verified,
            FileStatus::IntegrityFailed,
            FileStatus::Missing,
        ];
        for _ in 0..2000 {
            let st = RelayState::new(["f"]);
            st.record("f", FileStatus::Verified, "startup");
            let mut latest_recorded: Option<(u64, FileStatus)> = None;
            // In-flight checks: (seq, status they will report).
            let mut in_flight: Vec<(u64, FileStatus)> = Vec::new();
            for _ in 0..12 {
                let r = next();
                if in_flight.is_empty() || r % 2 == 0 {
                    let status = statuses[usize::try_from(r % 3).unwrap()];
                    in_flight.push((st.begin_check(), status));
                } else {
                    let i = usize::try_from(r % u64::try_from(in_flight.len()).unwrap()).unwrap();
                    let (seq, status) = in_flight.swap_remove(i);
                    let applied = st.record_check("f", status, "rrq", seq).is_some();
                    let should = latest_recorded.is_none_or(|(s, _)| seq >= s);
                    assert_eq!(applied, should, "seq {seq} latest {latest_recorded:?}");
                    if should {
                        latest_recorded = Some((seq, status));
                    }
                    let (_, want) = latest_recorded.unwrap();
                    assert_eq!(st.files(), vec![("f".to_owned(), want)]);
                    assert_eq!(st.content_available(), want == FileStatus::Verified);
                }
            }
        }
    }
}
