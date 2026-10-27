//! M2 exit criterion 1 at full size (plan M2 section 0 item 3(b),
//! section 10 "Large", WU-10): a **10.5 GiB, 12-edition** synthetic WIM
//! made by the usgp-image test builder goes through the real server
//! binary over mutual TLS on PostgreSQL: upload, check, edition listing,
//! declaration of edition 1 as windows-11 / enterprise / x64, import of a
//! builder-made x64 PE, a **Ready** package, signed package and content
//! manifests verified with the pinned content key, and a verified
//! re-download (every 8 MiB chunk digest and the whole-file digest,
//! against digests this test computed from the source).
//!
//! Memory stays bounded: the server's peak resident set (`VmHWM` in
//! `/proc/<pid>/status`, also sampled as `VmRSS` every 250 ms) must stay
//! under 256 MiB while 10.5 GiB pass through it twice. The test client
//! streams too; its own peak is printed for the record.
//!
//! The image's large file is a zero-filled resource written as a hole
//! (WU-5), so the source costs almost no disk where the filesystem
//! supports sparse files. The server's staging file and stored object are
//! real (one 10.5 GiB copy; staging is renamed into the store).
//!
//! Needs features `pg-integration` and `large-tests`, the
//! `USGP_TEST_PG_*` variables, a **fresh** database, Linux (procfs) and
//! at least 14 GiB free under the temporary directory (`TMPDIR`).
//! Without any of these the test **fails**; it never skips. When the
//! only problem is disk space, the failure message starts with
//! `NOT RUN: insufficient disk` so that the CI job can record NOT RUN
//! (never PASS) for it.
//!
//! Real Windows 11 Enterprise media through the same flow is manual test
//! MT-1 (NOT RUN until the owner runs it). The facts in this evidence are
//! `declared`, never `verified`.

#![cfg(all(feature = "pg-integration", feature = "large-tests"))]

#[cfg(test)]
pub mod common;

#[cfg(test)]
mod large {
    use std::path::Path;
    use std::process::Command;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use usgp_image::Compression;
    use usgp_image::testkit::builder::WimBuilder;
    use usgp_proto::WimCompression;

    use crate::common::Fixture;
    use crate::common::flow::{self, Expect, Source};
    use crate::common::pg::{PgSetup, text, var};
    use crate::common::stream::{Body, digest_bytes, digest_file};

    /// Editions in the large image (plan section 10).
    const EDITIONS: u32 = 12;

    /// Size of the zero-filled file in edition 1: 10.5 GiB.
    const ZERO_FILE_BYTES: u64 = 21 << 29;

    /// Free space required under the temporary directory (plan WU-10):
    /// one stored copy of the image (10.5 GiB) plus headroom.
    const REQUIRED_FREE_BYTES: u64 = 14 << 30;

    /// Bound on the server's peak resident set (plan section 10).
    const MAX_SERVER_RSS_BYTES: u64 = 256 << 20;

    /// Marker the CI job maps to NOT RUN.
    const NOT_RUN_DISK: &str = "NOT RUN: insufficient disk";

    /// Upload limit configured for this test (above the image size).
    const MAX_UPLOAD_BYTES: u64 = 16 << 30;

    fn editions() -> Vec<(String, String)> {
        (1..=EDITIONS)
            .map(|i| {
                (
                    format!("Synthetic Large Edition {i}"),
                    format!("Builder-made large edition {i}"),
                )
            })
            .collect()
    }

    /// Bytes available to an unprivileged user on the filesystem holding
    /// `dir`, from POSIX `df -P -k`.
    fn free_bytes(dir: &Path) -> u64 {
        let out = Command::new("df")
            .args(["-P", "-k"])
            .arg(dir)
            .output()
            .expect("run df");
        assert!(out.status.success(), "df failed: {}", text(&out.stderr));
        let stdout = text(&out.stdout);
        let line = stdout.lines().nth(1).expect("df output line");
        let kib: u64 = line
            .split_whitespace()
            .nth(3)
            .and_then(|v| v.parse().ok())
            .expect("df available column");
        kib * 1024
    }

    /// A `kB` value from a `/proc/<pid>/status` line, in bytes.
    fn status_kib(pid: &str, key: &str) -> Option<u64> {
        let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        let line = s.lines().find(|l| l.starts_with(key))?;
        let kib: u64 = line
            .trim_start_matches(key)
            .trim_start_matches(':')
            .split_whitespace()
            .next()?
            .parse()
            .ok()?;
        Some(kib * 1024)
    }

    /// Samples the child's `VmRSS` every 250 ms; keeps the maximum.
    struct RssSampler {
        stop: Arc<AtomicBool>,
        max: Arc<AtomicU64>,
        thread: std::thread::JoinHandle<()>,
    }

    impl RssSampler {
        fn start(pid: u32) -> Self {
            let stop = Arc::new(AtomicBool::new(false));
            let max = Arc::new(AtomicU64::new(0));
            let (s, m) = (Arc::clone(&stop), Arc::clone(&max));
            let pid = pid.to_string();
            let thread = std::thread::spawn(move || {
                while !s.load(Ordering::Relaxed) {
                    if let Some(rss) = status_kib(&pid, "VmRSS") {
                        m.fetch_max(rss, Ordering::Relaxed);
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }
            });
            Self { stop, max, thread }
        }

        fn finish(self) -> u64 {
            self.stop.store(true, Ordering::Relaxed);
            self.thread.join().unwrap();
            self.max.load(Ordering::Relaxed)
        }
    }

    /// Whole MiB, for messages.
    fn mib(b: u64) -> u64 {
        b >> 20
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn large_multi_edition_wim_to_ready_package() {
        let started = Instant::now();
        // Preflight. Database variables first (fail, never skip).
        let _ = var("USGP_TEST_PG_HOST");
        let f = Fixture::new("large-pg");
        let free = free_bytes(&f.scratch.dir);
        assert!(
            free >= REQUIRED_FREE_BYTES,
            "{NOT_RUN_DISK}: {} has {free} bytes free; the large upload needs \
             {REQUIRED_FREE_BYTES} (set TMPDIR to a larger filesystem)",
            f.scratch.dir.display()
        );
        assert!(
            Path::new("/proc/self/status").is_file(),
            "the large upload test needs Linux procfs to bound the server's memory"
        );

        // The 10.5 GiB, 12-edition XPRESS image (sparse zero file, no
        // integrity table: the builder would read the whole range back).
        let image_path = f.scratch.path("large.wim");
        let mut b = WimBuilder::new(Compression::Xpress).zero_file(ZERO_FILE_BYTES);
        for (name, desc) in editions() {
            b = b.image(&name, &desc);
        }
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&image_path)
            .unwrap();
        let info = b.write_to(&mut file).unwrap();
        drop(file);
        let len = std::fs::metadata(&image_path).unwrap().len();
        assert_eq!(len, info.len);
        assert!(len > ZERO_FILE_BYTES, "{len}");
        eprintln!("large: built {len} bytes in {:?}", started.elapsed());
        let t = Instant::now();
        let image = Source {
            body: Body::File(&image_path),
            digests: digest_file(&image_path),
        };
        assert_eq!(image.digests.size, len);
        eprintln!(
            "large: source digests ({} chunks) in {:?}",
            image.digests.chunks.len(),
            t.elapsed()
        );
        let pe_bytes = WimBuilder::new(Compression::Xpress)
            .image("Builder PE x64", "Preinstallation environment")
            .boot_index(1)
            .build()
            .unwrap()
            .0;
        let pe = Source {
            body: Body::Bytes(&pe_bytes),
            digests: digest_bytes(&pe_bytes),
        };

        // Server on PostgreSQL with an upload limit above the image.
        let pg = PgSetup::new(&f, |t| {
            let edited = t.replace(
                "max_upload_bytes = 1048576",
                &format!("max_upload_bytes = {MAX_UPLOAD_BYTES}"),
            );
            assert_ne!(edited, t, "fixture config changed shape");
            edited
        });
        pg.migrate_fresh();
        let admin_pem = f.scratch.path("operator.pem");
        let out = pg.enrol(admin_pem.to_str().unwrap(), "Large Operator");
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        let s = pg.serve();
        let pid = s.pid().to_string();
        let sampler = RssSampler::start(s.pid());

        let t = Instant::now();
        let eds = editions();
        flow::wim_to_ready_package(
            s.addr,
            &f,
            &image,
            &Expect {
                display_name: "Large Synthetic Image",
                compression: WimCompression::Xpress,
                editions: &eds,
                chosen: 1,
                ready_within: Duration::from_secs(600),
            },
            &pe,
            &f.audit_pub,
        )
        .await;
        eprintln!(
            "large: flow (upload, check, package, download) in {:?}",
            t.elapsed()
        );

        let sampled = sampler.finish();
        let hwm = status_kib(&pid, "VmHWM").expect("server VmHWM");
        let own = status_kib("self", "VmHWM").unwrap_or(0);
        eprintln!(
            "large: server peak RSS {} MiB (VmHWM), max sampled VmRSS {} MiB; \
             test client peak RSS {} MiB",
            mib(hwm),
            mib(sampled),
            mib(own)
        );
        assert!(
            hwm < MAX_SERVER_RSS_BYTES && sampled < MAX_SERVER_RSS_BYTES,
            "server memory not bounded: VmHWM {hwm} bytes, sampled VmRSS {sampled} bytes, \
             limit {MAX_SERVER_RSS_BYTES}"
        );

        let (code, lines) = pg.stop(s);
        assert_eq!(code, Some(0), "{}", lines.join("\n"));
        let all = lines.join("\n");
        for e in [
            "\"event\":\"content.upload.received\"",
            "\"event\":\"content.ready\"",
            "\"event\":\"content.manifest.signed\"",
            "\"event\":\"edition.declared\"",
            "\"event\":\"pe.declared\"",
            "\"event\":\"package.created\"",
            "\"event\":\"package.manifest.signed\"",
            "\"event\":\"content.download.completed\"",
            "\"event\":\"server.stop\"",
        ] {
            assert!(all.contains(e), "{e} missing:\n{all}");
        }
        assert!(!all.contains("\"event\":\"content.download.aborted\""));
        assert!(!all.contains("\"event\":\"content.integrity.failed\""));

        let out = pg.audit_verify(f.scratch.path("audit.pub").to_str().unwrap());
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}{}",
            text(&out.stdout),
            text(&out.stderr)
        );
        assert!(text(&out.stdout).contains("audit chain: intact"));
        eprintln!("large: total {:?}", started.elapsed());
    }
}
