//! Kinds and lifecycle states of content, uploads and packages.
//!
//! Wire text matches the database check constraints of plan section 3.4.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - closed value sets.
// - SPEC: specs/os-images.md#REQ-IMG-020 (status visible: receiving,
//   checking, ready, failed)
// - SPEC: specs/os-images.md#REQ-IMG-021 (receiving and checking always end
//   in ready or failed)
// - SPEC: specs/os-images.md "States and transitions" (image file and
//   package states)
// - SPEC: specs/os-images.md#REQ-IMG-038, decision 0014 (codecs accepted
//   in M2: none and XPRESS)

closed_enum!(
    /// What an uploaded content item is.
    ContentKind, "content kind" {
        /// A Windows installation image file (WIM).
        Image => "image",
        /// A Windows PE kit (WIM).
        Pe => "pe",
    }
);

closed_enum!(
    /// Lifecycle state of a content item (image file or PE kit).
    ContentState, "content state" {
        /// The upload is in progress.
        Receiving => "receiving",
        /// The whole file has arrived and is being checked.
        Checking => "checking",
        /// Checked and recorded with its digest; usable.
        Ready => "ready",
        /// Interrupted or failed a check; a reason is given.
        Failed => "failed",
        /// Removed by an operator.
        Deleted => "deleted",
    }
);

impl ContentState {
    /// `true` for states that always end in Ready or Failed (REQ-IMG-021).
    #[must_use]
    pub const fn is_in_progress(self) -> bool {
        matches!(self, Self::Receiving | Self::Checking)
    }
}

closed_enum!(
    /// State of an upload session.
    UploadState, "upload state" {
        /// Created; no body received yet.
        Open => "open",
        /// The body is being received.
        Streaming => "streaming",
        /// The body arrived in full.
        Complete => "complete",
        /// The body was interrupted or did not match.
        Failed => "failed",
        /// Cancelled by the operator.
        Cancelled => "cancelled",
    }
);

closed_enum!(
    /// Usability of a package (M2: `ready` or `not_usable`, plan section
    /// 3.2).
    PackageStatus, "package status" {
        /// All referenced content is ready and the edition is in scope; the
        /// package manifest is signed.
        Ready => "ready",
        /// Something it refers to is not ready, unknown or out of scope; a
        /// reason is given.
        NotUsable => "not_usable",
    }
);

closed_enum!(
    /// Resource compression of a WIM file that M2 accepts (decision 0014).
    /// Files using any other method are refused at the check and never
    /// reach a manifest.
    WimCompression, "compression" {
        /// Uncompressed resources.
        None => "none",
        /// XPRESS (LZ77+Huffman, [MS-XCA]).
        Xpress => "xpress",
    }
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_text_matches_db_constraints() {
        let states: Vec<_> = ContentState::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(
            states,
            ["receiving", "checking", "ready", "failed", "deleted"]
        );
        let up: Vec<_> = UploadState::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(up, ["open", "streaming", "complete", "failed", "cancelled"]);
        let kinds: Vec<_> = ContentKind::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(kinds, ["image", "pe"]);
        let pk: Vec<_> = PackageStatus::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(pk, ["ready", "not_usable"]);
    }

    #[test]
    fn in_progress() {
        assert!(ContentState::Receiving.is_in_progress());
        assert!(ContentState::Checking.is_in_progress());
        assert!(!ContentState::Ready.is_in_progress());
        assert!(!ContentState::Failed.is_in_progress());
    }

    #[test]
    fn refused_codecs_have_no_wire_value() {
        for bad in ["lzx", "lzms", "LZX", "XPRESS"] {
            assert_eq!(WimCompression::parse(bad), None);
        }
    }
}
