//! Whether an edition or a PE is inside the M2 support scope (decisions
//! 0009 and 0013 item 3): only Windows 11, plain Enterprise, x64 images,
//! and x64 PEs, can make a package ready.
//!
//! The input is the reconciled facts only. There is no feature-update
//! input, so no rule can depend on it (REQ-OS-008).

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-7 (Least Functionality) - only the supported OS scope
//   can become ready; everything else is refused with a named reason.
// - SPEC: specs/os-support.md#REQ-OS-001, #REQ-OS-002, #REQ-OS-004,
//   #REQ-OS-007, #REQ-OS-008, #REQ-OS-009, #REQ-OS-010 (first sentence)
// - SPEC: specs/preinstall-env.md#REQ-PE-005
// - DECISION: docs/decisions/0009-m2-image-scope.md,
//   docs/decisions/0013-operator-declared-image-facts.md (item 3)

use usgp_proto::facts::{Architecture, Edition, EditionFacts, Release, SupportState};
use usgp_proto::{ErrorCode, codes};

/// Support status with the reasons that decided it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupportStatus {
    /// Inside the M2 scope.
    Supported,
    /// Outside the scope. One reason per failing fact, in release,
    /// edition, architecture order (for example
    /// `release_not_supported:windows-10`); never empty.
    NotSupported {
        /// The failing facts.
        reasons: Vec<ErrorCode>,
    },
    /// Not known (no declaration): blocks readiness (REQ-OS-009).
    Unknown {
        /// `os_support_unknown`.
        reason: ErrorCode,
    },
}

impl SupportStatus {
    /// The wire state.
    #[must_use]
    pub fn state(&self) -> SupportState {
        match self {
            Self::Supported => SupportState::Supported,
            Self::NotSupported { .. } => SupportState::NotSupported,
            Self::Unknown { .. } => SupportState::Unknown,
        }
    }

    /// The first reason, if not supported or unknown.
    #[must_use]
    pub fn reason(&self) -> Option<&ErrorCode> {
        match self {
            Self::Supported => None,
            Self::NotSupported { reasons } => reasons.first(),
            Self::Unknown { reason } => Some(reason),
        }
    }
}

fn reason(base: &ErrorCode, value: &str) -> ErrorCode {
    // Every proto value is valid code syntax; fall back to the base code
    // rather than fail if that ever changes.
    base.with_param(value).unwrap_or_else(|_| base.clone())
}

/// Evaluates an edition's reconciled facts; `None` (undeclared) is
/// [`SupportStatus::Unknown`].
#[must_use]
pub fn evaluate(facts: Option<&EditionFacts>) -> SupportStatus {
    let Some(f) = facts else {
        return SupportStatus::Unknown {
            reason: codes::OS_SUPPORT_UNKNOWN,
        };
    };
    let mut reasons = Vec::new();
    // REQ-OS-001, REQ-OS-007: Windows 11 only.
    if f.release.value != Release::Windows11 {
        reasons.push(reason(
            &codes::RELEASE_NOT_SUPPORTED,
            f.release.value.as_str(),
        ));
    }
    // REQ-OS-004; decision 0013 item 3: plain Enterprise only (not LTSC,
    // not IoT Enterprise).
    if f.edition.value != Edition::Enterprise {
        reasons.push(reason(
            &codes::EDITION_NOT_SUPPORTED,
            f.edition.value.as_str(),
        ));
    }
    // REQ-OS-002: x64 only.
    if f.architecture.value != Architecture::X64 {
        reasons.push(reason(
            &codes::ARCHITECTURE_NOT_SUPPORTED,
            f.architecture.value.as_str(),
        ));
    }
    if reasons.is_empty() {
        SupportStatus::Supported
    } else {
        SupportStatus::NotSupported { reasons }
    }
}

/// Evaluates a PE's declared (or verified) architecture: x64 only
/// (REQ-PE-005, REQ-OS-010 first sentence).
#[must_use]
pub fn evaluate_pe(architecture: Architecture) -> SupportStatus {
    if architecture == Architecture::X64 {
        SupportStatus::Supported
    } else {
        SupportStatus::NotSupported {
            reasons: vec![reason(
                &codes::PE_ARCHITECTURE_NOT_SUPPORTED,
                architecture.as_str(),
            )],
        }
    }
}

#[cfg(test)]
mod tests {
    use usgp_proto::facts::Fact;

    use super::*;

    fn facts(r: Release, e: Edition, a: Architecture) -> EditionFacts {
        EditionFacts {
            release: Fact::declared(r),
            edition: Fact::declared(e),
            architecture: Fact::declared(a),
        }
    }

    fn codes_of(s: &SupportStatus) -> Vec<String> {
        match s {
            SupportStatus::NotSupported { reasons } => {
                reasons.iter().map(|c| c.as_str().to_owned()).collect()
            }
            _ => Vec::new(),
        }
    }

    #[test]
    fn only_windows_11_enterprise_x64_supported() {
        let mut supported = 0;
        for &r in Release::ALL {
            for &e in Edition::ALL {
                for &a in Architecture::ALL {
                    let s = evaluate(Some(&facts(r, e, a)));
                    let ok = r == Release::Windows11
                        && e == Edition::Enterprise
                        && a == Architecture::X64;
                    assert_eq!(s == SupportStatus::Supported, ok, "{r:?} {e:?} {a:?}");
                    if ok {
                        supported += 1;
                    } else {
                        assert_eq!(s.state(), SupportState::NotSupported);
                        assert!(s.reason().is_some());
                    }
                }
            }
        }
        assert_eq!(supported, 1);
    }

    #[test]
    fn windows_10_refused() {
        let s = evaluate(Some(&facts(
            Release::Windows10,
            Edition::Enterprise,
            Architecture::X64,
        )));
        assert_eq!(codes_of(&s), ["release_not_supported:windows-10"]);
    }

    #[test]
    fn other_release_refused() {
        let s = evaluate(Some(&facts(
            Release::Other,
            Edition::Enterprise,
            Architecture::X64,
        )));
        assert_eq!(codes_of(&s), ["release_not_supported:other"]);
    }

    #[test]
    fn x86_arm64_arm_refused() {
        for (a, code) in [
            (Architecture::X86, "architecture_not_supported:x86"),
            (Architecture::Arm64, "architecture_not_supported:arm64"),
            (Architecture::Arm, "architecture_not_supported:arm"),
        ] {
            let s = evaluate(Some(&facts(Release::Windows11, Edition::Enterprise, a)));
            assert_eq!(codes_of(&s), [code]);
        }
    }

    #[test]
    fn pro_home_education_refused() {
        for e in [
            Edition::Pro,
            Edition::Home,
            Edition::Education,
            Edition::Other,
        ] {
            let s = evaluate(Some(&facts(Release::Windows11, e, Architecture::X64)));
            assert_eq!(
                codes_of(&s),
                [format!("edition_not_supported:{}", e.as_str())]
            );
        }
    }

    #[test]
    fn ltsc_refused() {
        let s = evaluate(Some(&facts(
            Release::Windows11,
            Edition::EnterpriseLtsc,
            Architecture::X64,
        )));
        assert_eq!(codes_of(&s), ["edition_not_supported:enterprise-ltsc"]);
    }

    #[test]
    fn iot_refused() {
        let s = evaluate(Some(&facts(
            Release::Windows11,
            Edition::IotEnterprise,
            Architecture::X64,
        )));
        assert_eq!(codes_of(&s), ["edition_not_supported:iot-enterprise"]);
    }

    #[test]
    fn every_failing_fact_is_named() {
        let s = evaluate(Some(&facts(
            Release::Windows10,
            Edition::Pro,
            Architecture::Arm64,
        )));
        assert_eq!(
            codes_of(&s),
            [
                "release_not_supported:windows-10",
                "edition_not_supported:pro",
                "architecture_not_supported:arm64"
            ]
        );
    }

    #[test]
    fn undeclared_is_unknown() {
        let s = evaluate(None);
        assert_eq!(s.state(), SupportState::Unknown);
        assert_eq!(
            s.reason().map(ErrorCode::as_str),
            Some("os_support_unknown")
        );
    }

    #[test]
    fn verified_and_declared_treated_alike() {
        let f = EditionFacts {
            release: Fact::verified(Release::Windows11),
            edition: Fact::declared(Edition::Enterprise),
            architecture: Fact::verified(Architecture::X64),
        };
        assert_eq!(evaluate(Some(&f)), SupportStatus::Supported);
    }

    #[test]
    fn no_feature_update_input() {
        // REQ-OS-008: `evaluate` takes only release, edition and
        // architecture; EditionFacts has no feature-update field. This
        // test pins the signature.
        let f: fn(Option<&EditionFacts>) -> SupportStatus = evaluate;
        assert_eq!(f(None).state(), SupportState::Unknown);
    }

    #[test]
    fn pe_x64_only() {
        assert_eq!(evaluate_pe(Architecture::X64), SupportStatus::Supported);
        for a in [Architecture::X86, Architecture::Arm64, Architecture::Arm] {
            let s = evaluate_pe(a);
            assert_eq!(
                codes_of(&s),
                [format!("pe_architecture_not_supported:{}", a.as_str())]
            );
        }
    }
}
