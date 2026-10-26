//! SI-7 tamper suite (M1 exit criterion 2): any change to a published file
//! makes the relay refuse to serve it, moves the service to
//! `RunningMissingContent` (offers stop), and a re-check after the file is
//! restored moves it back to `Running`.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SI-7, SA-11
//! - SPEC: specs/boot-network.md#REQ-BOOT-033, #REQ-BOOT-041, #REQ-BOOT-052

#[cfg(test)]
pub mod common;

#[cfg(test)]
mod integrity {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use usgp_relay::content::{ContentError, ContentLoadError, ContentStore};
    use usgp_relay::limits::Counters;
    use usgp_relay::state::{FileStatus, ServiceState};
    use usgp_relay::tftp::{Disposition, TftpListener, TftpShared};
    use usgp_tftp::{Opcode, Packet, encode_request, parse};

    use crate::common::{
        MemFactory, MemNet, PROGRAM, Scratch, bytes, config, content, iface, set_mode,
    };

    const SIZE: usize = 5000;

    async fn published(tag: &str) -> (Scratch, Arc<ContentStore>, Vec<u8>) {
        let s = Scratch::new(tag);
        let data = bytes(SIZE, 7);
        s.publish(&[(PROGRAM, &data)]);
        let c = content(&config(&s)).await;
        assert_eq!(c.state().current(), ServiceState::Running);
        assert!(c.offerable_program().is_some());
        (s, c, data)
    }

    /// Asserts the tampered state, restores the file, re-checks, and
    /// asserts recovery.
    async fn expect_refused_then_recover(
        s: &Scratch,
        c: &ContentStore,
        good: &[u8],
        expected: ContentError,
    ) {
        assert_eq!(
            c.get_verified(PROGRAM.as_bytes()).await.unwrap_err(),
            expected
        );
        assert_eq!(c.state().current(), ServiceState::RunningMissingContent);
        assert!(c.offerable_program().is_none(), "offers must stop");
        let path = s.root().join(PROGRAM);
        let _ = std::fs::remove_file(&path);
        s.write_boot_file(PROGRAM, good);
        c.recheck_all("recheck").await;
        assert_eq!(c.state().current(), ServiceState::Running);
        assert!(c.offerable_program().is_some());
        let served = c.get_verified(PROGRAM.as_bytes()).await.unwrap();
        assert_eq!(&*served, good);
    }

    async fn flip(at: usize, tag: &str) {
        let (s, c, data) = published(tag).await;
        let mut bad = data.clone();
        bad[at] ^= 0x01;
        s.write_boot_file(PROGRAM, &bad);
        expect_refused_then_recover(&s, &c, &data, ContentError::IntegrityFailed).await;
    }

    #[tokio::test]
    async fn flip_first_byte() {
        flip(0, "flip-first").await;
    }

    #[tokio::test]
    async fn flip_middle_byte() {
        flip(SIZE / 2, "flip-middle").await;
    }

    #[tokio::test]
    async fn flip_last_byte() {
        flip(SIZE - 1, "flip-last").await;
    }

    #[tokio::test]
    async fn truncated_file_refused() {
        let (s, c, data) = published("truncate").await;
        s.write_boot_file(PROGRAM, &data[..SIZE - 1]);
        expect_refused_then_recover(&s, &c, &data, ContentError::IntegrityFailed).await;
    }

    #[tokio::test]
    async fn appended_file_refused() {
        let (s, c, data) = published("append").await;
        let mut longer = data.clone();
        longer.push(0);
        s.write_boot_file(PROGRAM, &longer);
        expect_refused_then_recover(&s, &c, &data, ContentError::IntegrityFailed).await;
    }

    #[tokio::test]
    async fn symlink_refused() {
        let (s, c, data) = published("symlink").await;
        // A link to an identical copy elsewhere is still refused: the
        // final component must not be a link (O_NOFOLLOW).
        let elsewhere = s.dir.join("copy.efi");
        std::fs::write(&elsewhere, &data).unwrap();
        let path = s.root().join(PROGRAM);
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &path).unwrap();
        expect_refused_then_recover(&s, &c, &data, ContentError::IntegrityFailed).await;
    }

    #[tokio::test]
    async fn fifo_refused_without_blocking() {
        let (s, c, data) = published("fifo").await;
        let path = s.root().join(PROGRAM);
        std::fs::remove_file(&path).unwrap();
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success());
        let r = tokio::time::timeout(Duration::from_secs(10), c.get_verified(PROGRAM.as_bytes()))
            .await
            .expect("a FIFO must not block the verifier");
        assert_eq!(r.unwrap_err(), ContentError::IntegrityFailed);
        expect_refused_then_recover(&s, &c, &data, ContentError::IntegrityFailed).await;
    }

    #[tokio::test]
    async fn directory_in_place_of_file_refused() {
        let (s, c, data) = published("dir").await;
        let path = s.root().join(PROGRAM);
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(
            c.get_verified(PROGRAM.as_bytes()).await.unwrap_err(),
            ContentError::IntegrityFailed
        );
        std::fs::remove_dir(&path).unwrap();
        s.write_boot_file(PROGRAM, &data);
        c.recheck_all("recheck").await;
        assert_eq!(c.state().current(), ServiceState::Running);
    }

    #[tokio::test]
    async fn missing_file_reported_missing() {
        let (s, c, data) = published("missing").await;
        std::fs::remove_file(s.root().join(PROGRAM)).unwrap();
        assert_eq!(
            c.get_verified(PROGRAM.as_bytes()).await.unwrap_err(),
            ContentError::Missing
        );
        assert_eq!(
            c.state().files(),
            vec![(PROGRAM.to_owned(), FileStatus::Missing)]
        );
        expect_refused_then_recover(&s, &c, &data, ContentError::Missing).await;
    }

    #[tokio::test]
    async fn oversize_file_refused() {
        // The manifest allows the size, but the file on disk is larger
        // than tftp.max_file_size_bytes: refused before it is read.
        let s = Scratch::new("oversize");
        let data = bytes(100, 3);
        s.publish(&[(PROGRAM, &data)]);
        let mut cfg = config(&s);
        cfg.tftp.max_file_size = 100;
        let c = content(&cfg).await;
        assert_eq!(c.state().current(), ServiceState::Running);
        s.write_boot_file(PROGRAM, &bytes(101, 3));
        expect_refused_then_recover(&s, &c, &data, ContentError::IntegrityFailed).await;
    }

    #[tokio::test]
    async fn unpublished_name_never_read() {
        let (s, c, _) = published("unpublished").await;
        s.write_boot_file("other.efi", b"not published");
        assert_eq!(
            c.get_verified(b"other.efi").await.unwrap_err(),
            ContentError::NotPublished
        );
        // An unpublished name does not change the service state.
        assert_eq!(c.state().current(), ServiceState::Running);
    }

    #[tokio::test]
    async fn startup_with_tampered_file_is_missing_content() {
        let s = Scratch::new("startup-tamper");
        let data = bytes(64, 1);
        s.publish(&[(PROGRAM, &data)]);
        s.write_boot_file(PROGRAM, &bytes(64, 2));
        let c = content(&config(&s)).await;
        assert_eq!(c.state().current(), ServiceState::RunningMissingContent);
        assert!(c.offerable_program().is_none());
    }

    #[tokio::test]
    async fn second_file_failure_stops_offers() {
        let s = Scratch::new("second");
        let a = bytes(64, 1);
        let b = bytes(64, 2);
        s.publish(&[(PROGRAM, &a), ("extra.bin", &b)]);
        let c = content(&config(&s)).await;
        assert_eq!(c.state().current(), ServiceState::Running);
        s.write_boot_file("extra.bin", &bytes(64, 9));
        assert!(c.get_verified(b"extra.bin").await.is_err());
        assert!(c.offerable_program().is_none());
        // The program itself is still served (it still matches).
        assert!(c.get_verified(PROGRAM.as_bytes()).await.is_ok());
    }

    #[tokio::test]
    async fn concurrent_reads_share_one_buffer() {
        let (_s, c, _) = published("share").await;
        let one = c.get_verified(PROGRAM.as_bytes()).await.unwrap();
        let two = c.get_verified(PROGRAM.as_bytes()).await.unwrap();
        assert!(Arc::ptr_eq(&one, &two));
    }

    /// SEC-004: a directory component below the boot root that is a
    /// symbolic link is never followed, even when the file it leads to
    /// matches the manifest digest.
    #[tokio::test]
    async fn symlinked_directory_under_root_refused() {
        let s = Scratch::new("symdir");
        let data = bytes(SIZE, 9);
        let name = "x64/boot.efi";
        s.publish(&[(PROGRAM, &data), (name, &data)]);
        let c = content(&config(&s)).await;
        assert!(c.get_verified(name.as_bytes()).await.is_ok());
        // Move the real directory out of the root and link to it.
        let outside = s.dir.join("outside");
        std::fs::rename(s.root().join("x64"), &outside).unwrap();
        std::os::unix::fs::symlink(&outside, s.root().join("x64")).unwrap();
        assert_eq!(
            c.get_verified(name.as_bytes()).await.unwrap_err(),
            ContentError::IntegrityFailed
        );
        assert_eq!(c.state().current(), ServiceState::RunningMissingContent);
        // Restoring a real directory recovers.
        std::fs::remove_file(s.root().join("x64")).unwrap();
        std::fs::rename(&outside, s.root().join("x64")).unwrap();
        c.recheck_all("recheck").await;
        assert_eq!(c.state().current(), ServiceState::Running);
    }

    #[tokio::test]
    async fn manifest_must_publish_the_program() {
        let s = Scratch::new("noprog");
        s.publish(&[("other.efi", b"x")]);
        let cfg = config(&s);
        let e = ContentStore::load(
            &cfg.boot.manifest,
            &cfg.boot.root,
            &cfg.boot.uefi_x64_program,
            cfg.tftp.max_file_size,
            1,
            &cfg.trust,
        )
        .unwrap_err();
        assert!(matches!(e, ContentLoadError::ProgramNotPublished), "{e:?}");
    }

    #[tokio::test]
    async fn manifest_entry_larger_than_limit_refused() {
        let s = Scratch::new("entry-large");
        s.publish(&[(PROGRAM, &bytes(10, 1))]);
        let cfg = config(&s);
        let e = ContentStore::load(
            &cfg.boot.manifest,
            &cfg.boot.root,
            &cfg.boot.uefi_x64_program,
            9,
            1,
            &cfg.trust,
        )
        .unwrap_err();
        assert!(matches!(e, ContentLoadError::EntryTooLarge), "{e:?}");
    }

    #[tokio::test]
    async fn invalid_manifest_refused() {
        let s = Scratch::new("bad-manifest");
        s.publish(&[(PROGRAM, &bytes(10, 1))]);
        std::fs::write(s.manifest_path(), "schema_version = 2\n").unwrap();
        set_mode(&s.manifest_path(), 0o644);
        let cfg = config(&s);
        let e = ContentStore::load(
            &cfg.boot.manifest,
            &cfg.boot.root,
            &cfg.boot.uefi_x64_program,
            cfg.tftp.max_file_size,
            1,
            &cfg.trust,
        )
        .unwrap_err();
        assert!(matches!(e, ContentLoadError::Manifest(_)), "{e:?}");
    }

    /// End to end through TFTP: after one byte changes, an RRQ gets
    /// ERROR 1 and no DATA (exit criterion 2).
    #[tokio::test]
    async fn tampered_file_rrq_gets_error1() {
        let (s, c, data) = published("tftp-tamper").await;
        let net = MemNet::new();
        let cfg = config(&s);
        let shed = Arc::new(Mutex::new(Counters::default()));
        let shared = TftpShared::new(&cfg.limits, shed, std::time::Instant::now());
        let listener = TftpListener::new(
            iface(),
            Arc::clone(&c),
            cfg.tftp_listener_config(),
            MemFactory {
                net: Arc::clone(&net),
                ip: IpAddr::V4(crate::common::IFACE_ADDR),
            },
            shared,
        );
        let client = net.bind(IpAddr::V4(Ipv4Addr::new(10, 20, 1, 50)));
        let rrq = encode_request(Opcode::Rrq, PROGRAM.as_bytes(), b"octet", &[]);

        // Untampered: DATA 1 arrives.
        assert_eq!(
            listener.handle_request(client.addr, &rrq),
            Disposition::Started
        );
        let (pkt, _) = client.recv().await;
        assert!(matches!(parse(&pkt), Ok(Packet::Data { block: 1, .. })));

        let mut bad = data.clone();
        bad[100] ^= 0x80;
        s.write_boot_file(PROGRAM, &bad);
        let client2 = net.bind(IpAddr::V4(Ipv4Addr::new(10, 20, 1, 51)));
        assert_eq!(
            listener.handle_request(client2.addr, &rrq),
            Disposition::Started
        );
        let (pkt, from) = client2.recv().await;
        assert!(
            matches!(parse(&pkt), Ok(Packet::Error { code: 1, .. })),
            "{pkt:?}"
        );
        assert_ne!(
            from,
            SocketAddr::new(IpAddr::V4(crate::common::IFACE_ADDR), 69)
        );
        assert_eq!(c.state().current(), ServiceState::RunningMissingContent);
        assert!(
            client2
                .recv_within(Duration::from_millis(200))
                .await
                .is_none(),
            "nothing after the ERROR"
        );
    }
}
