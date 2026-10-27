//! A package's status: `ready` or `not_usable` with a reason (plan M2
//! WU-6; REQ-IMG-001, REQ-IMG-020, REQ-OS-009).
//!
//! Pure: the inputs are the states and facts the caller read inside its
//! transaction, and the caller stores the result (and, on `ready`, signs
//! the package manifest) in that same transaction.

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-7 (Least Functionality), SI-7 - only verified, Ready,
//   in-scope content makes a usable package.
// - SPEC: specs/os-images.md#REQ-IMG-001, #REQ-IMG-020
// - SPEC: specs/os-support.md#REQ-OS-001, #REQ-OS-002, #REQ-OS-004,
//   #REQ-OS-009 (unknown support blocks readiness)
// - SPEC: specs/preinstall-env.md#REQ-PE-005
// - Decisions 0009, 0013 item 3

use usgp_image::os_support::{SupportStatus, evaluate_pe};
use usgp_proto::{Architecture, ContentState, ErrorCode, SupportState, codes};

/// What the status depends on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusInputs {
    /// The image file's state.
    pub image_state: ContentState,
    /// The chosen edition's support status.
    pub edition_support: SupportState,
    /// Its reason (for `not_supported` and `unknown`).
    pub edition_reason: Option<ErrorCode>,
    /// The PE's state.
    pub pe_state: ContentState,
    /// The PE's architecture.
    pub pe_architecture: Architecture,
}

/// The computed status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Computed {
    /// Usable; the manifest is signed.
    Ready,
    /// Not usable, with the first reason found.
    NotUsable(ErrorCode),
}

fn param(base: &ErrorCode, p: &str) -> ErrorCode {
    base.with_param(p).unwrap_or_else(|_| base.clone())
}

/// The status for `inputs`. Reasons are checked in this order: image not
/// Ready, PE not Ready, edition support, PE architecture.
#[must_use]
pub fn compute(inputs: &StatusInputs) -> Computed {
    if inputs.image_state != ContentState::Ready {
        return Computed::NotUsable(param(&codes::NOT_READY_CONTENT, "image"));
    }
    if inputs.pe_state != ContentState::Ready {
        return Computed::NotUsable(param(&codes::NOT_READY_CONTENT, "pe"));
    }
    match inputs.edition_support {
        SupportState::Supported => {}
        SupportState::Unknown => {
            return Computed::NotUsable(
                inputs
                    .edition_reason
                    .clone()
                    .unwrap_or(codes::OS_SUPPORT_UNKNOWN),
            );
        }
        SupportState::NotSupported => {
            return Computed::NotUsable(inputs.edition_reason.clone().unwrap_or(codes::OS_SCOPE));
        }
    }
    match evaluate_pe(inputs.pe_architecture) {
        SupportStatus::Supported => Computed::Ready,
        other => Computed::NotUsable(
            other
                .reason()
                .cloned()
                .unwrap_or(codes::PE_ARCHITECTURE_NOT_SUPPORTED),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok() -> StatusInputs {
        StatusInputs {
            image_state: ContentState::Ready,
            edition_support: SupportState::Supported,
            edition_reason: None,
            pe_state: ContentState::Ready,
            pe_architecture: Architecture::X64,
        }
    }

    #[test]
    fn ready_only_when_everything_is_ready_and_in_scope() {
        assert_eq!(compute(&ok()), Computed::Ready);
        for s in ContentState::ALL {
            if *s == ContentState::Ready {
                continue;
            }
            let i = StatusInputs {
                image_state: *s,
                ..ok()
            };
            assert_eq!(
                compute(&i),
                Computed::NotUsable(ErrorCode::new("not_ready_content:image").unwrap())
            );
            let p = StatusInputs {
                pe_state: *s,
                ..ok()
            };
            assert_eq!(
                compute(&p),
                Computed::NotUsable(ErrorCode::new("not_ready_content:pe").unwrap())
            );
        }
        let u = StatusInputs {
            edition_support: SupportState::Unknown,
            edition_reason: Some(codes::OS_SUPPORT_UNKNOWN),
            ..ok()
        };
        assert_eq!(compute(&u), Computed::NotUsable(codes::OS_SUPPORT_UNKNOWN));
        let n = StatusInputs {
            edition_support: SupportState::NotSupported,
            edition_reason: Some(ErrorCode::new("edition_not_supported:pro").unwrap()),
            ..ok()
        };
        assert_eq!(
            compute(&n),
            Computed::NotUsable(ErrorCode::new("edition_not_supported:pro").unwrap())
        );
        for a in [Architecture::X86, Architecture::Arm64, Architecture::Arm] {
            let p = StatusInputs {
                pe_architecture: a,
                ..ok()
            };
            assert!(matches!(compute(&p), Computed::NotUsable(c)
                if c.base() == "pe_architecture_not_supported"));
        }
    }
}
