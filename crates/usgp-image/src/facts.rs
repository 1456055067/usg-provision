//! Edition and PE facts read from the file and reconciled with the
//! operator's declaration (decision 0013; REQ-IMG-043 items 2 and 3).
//!
//! A fact is read from the file only through a [`FactRule`] in a
//! [`FactTable`]: "the image's XML element at `path` with text `text`
//! states this value". The product table, [`FactTable::DOCUMENTED`], is
//! **empty in M2**: no Microsoft source we may read says which XML element
//! records release, edition or architecture (OPEN-WIM-8), and our DISM
//! samples cannot show it (OBS-014). So every M2 fact is `declared`.
//! Nothing is ever inferred from `NAME` or `DESCRIPTION` text.
//!
//! Adding a rule is a reviewed change; each rule must carry a
//! `// FORMAT:` citation of a `wim.md` section or an `OBS-nnn` record.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - closed value sets;
//   exact text match only.
// - NIST 800-53: AU-10 (Non-repudiation, basis) - every fact carries its
//   source (declared or verified).
// - SPEC: specs/os-images.md#REQ-IMG-043 (declared, cross-checked, marked)
// - SPEC: specs/preinstall-env.md#REQ-PE-005 (PE architecture declared and
//   cross-checked)
// - DECISION: docs/decisions/0013-operator-declared-image-facts.md
//
// POAM: SI-7 / CM-6 - image and PE facts are operator-declared
// (FactTable::DOCUMENTED empty, OPEN-WIM-8); compensating: identity-bound
// audit, "declared" label in views and signed manifests.

use usgp_proto::ErrorCode;
use usgp_proto::codes;
use usgp_proto::facts::{Architecture, Edition, EditionFacts, Fact, Release};

use crate::wim::xml::WimXmlImage;

/// Which fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FactKind {
    /// Windows release.
    Release,
    /// Windows edition.
    Edition,
    /// Processor architecture.
    Architecture,
}

impl FactKind {
    /// Stable name (`release`, `edition`, `architecture`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::Edition => "edition",
            Self::Architecture => "architecture",
        }
    }
}

/// A value a rule states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactValue {
    /// A release.
    Release(Release),
    /// An edition.
    Edition(Edition),
    /// An architecture.
    Architecture(Architecture),
}

/// "The leaf at `path` with exactly `text` states `value`."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactRule {
    /// Leaf path below `IMAGE` ([`crate::XmlLeaf::path`]).
    pub path: &'static str,
    /// Exact text the leaf must hold.
    pub text: &'static str,
    /// The fact it states.
    pub value: FactValue,
}

/// A set of documented rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactTable(&'static [FactRule]);

impl FactTable {
    /// The product table. Empty in M2: no documented source (OPEN-WIM-8,
    /// OBS-014; decision 0013).
    pub const DOCUMENTED: Self = Self(&[]);

    /// A table of `rules` (tests use their own tables).
    #[must_use]
    pub const fn new(rules: &'static [FactRule]) -> Self {
        Self(rules)
    }

    /// The rules.
    #[must_use]
    pub const fn rules(&self) -> &'static [FactRule] {
        self.0
    }
}

/// What the file says about one fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFact<T> {
    /// No rule matched.
    NotStated,
    /// Every matching rule stated this value.
    Stated(T),
    /// Matching rules stated different values; the file contradicts
    /// itself, so no declaration can be verified against it.
    Inconsistent,
}

impl<T: PartialEq + Copy> FileFact<T> {
    fn add(&mut self, v: T) {
        *self = match *self {
            Self::NotStated => Self::Stated(v),
            Self::Stated(old) if old == v => Self::Stated(old),
            Self::Stated(_) | Self::Inconsistent => Self::Inconsistent,
        };
    }
}

/// What the file states, fact by fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileFacts {
    /// Release.
    pub release: FileFact<Release>,
    /// Edition.
    pub edition: FileFact<Edition>,
    /// Architecture.
    pub architecture: FileFact<Architecture>,
}

/// Reads the facts `table` documents from one image's XML.
#[must_use]
pub fn read_file_facts(image: &WimXmlImage, table: &FactTable) -> FileFacts {
    let mut f = FileFacts {
        release: FileFact::NotStated,
        edition: FileFact::NotStated,
        architecture: FileFact::NotStated,
    };
    for rule in table.rules() {
        let hit = image
            .elements
            .iter()
            .any(|l| l.path == rule.path && l.text == rule.text);
        if !hit {
            continue;
        }
        match rule.value {
            FactValue::Release(v) => f.release.add(v),
            FactValue::Edition(v) => f.edition.add(v),
            FactValue::Architecture(v) => f.architecture.add(v),
        }
    }
    f
}

/// The operator's declaration for one edition (decision 0013 item 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Declared {
    /// Declared release.
    pub release: Release,
    /// Declared edition.
    pub edition: Edition,
    /// Declared architecture.
    pub architecture: Architecture,
}

/// A declared fact that the file contradicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Contradiction {
    /// Which fact.
    pub fact: FactKind,
    /// The declared value (`as_str` of the proto enum).
    pub declared: &'static str,
    /// The file's value, or `inconsistent` if the file states several.
    pub file: &'static str,
}

impl Contradiction {
    /// `declaration_contradicts_file:<fact>` (decision 0013 item 2).
    #[must_use]
    pub fn reason_code(&self) -> ErrorCode {
        codes::DECLARATION_CONTRADICTS_FILE
            .with_param(self.fact.as_str())
            .unwrap_or(codes::DECLARATION_CONTRADICTS_FILE)
    }

    /// Operator text naming the fact and both values.
    #[must_use]
    pub fn operator_message(&self) -> String {
        format!(
            "declared {} {} contradicts the image file ({})",
            self.fact.as_str(),
            self.declared,
            self.file
        )
    }
}

const INCONSISTENT: &str = "inconsistent";

fn one<T: Copy + PartialEq>(
    kind: FactKind,
    declared: T,
    file: FileFact<T>,
    name: fn(T) -> &'static str,
) -> Result<Fact<T>, Contradiction> {
    match file {
        FileFact::NotStated => Ok(Fact::declared(declared)),
        FileFact::Stated(v) if v == declared => Ok(Fact::verified(declared)),
        FileFact::Stated(v) => Err(Contradiction {
            fact: kind,
            declared: name(declared),
            file: name(v),
        }),
        FileFact::Inconsistent => Err(Contradiction {
            fact: kind,
            declared: name(declared),
            file: INCONSISTENT,
        }),
    }
}

/// Reconciles a declaration with the file (decision 0013 item 2): each
/// fact the file does not state is `declared`; each it states and agrees
/// with is `verified`; the first that disagrees (release, edition,
/// architecture order) is a [`Contradiction`].
///
/// # Errors
///
/// [`Contradiction`] naming the first fact that disagrees.
pub fn reconcile(d: &Declared, f: &FileFacts) -> Result<EditionFacts, Contradiction> {
    Ok(EditionFacts {
        release: one(FactKind::Release, d.release, f.release, Release::as_str)?,
        edition: one(FactKind::Edition, d.edition, f.edition, Edition::as_str)?,
        architecture: one(
            FactKind::Architecture,
            d.architecture,
            f.architecture,
            Architecture::as_str,
        )?,
    })
}

/// Reconciles a PE's declared architecture with the file (REQ-PE-005).
/// The kit version is not stated by any documented XML element and is
/// always `declared`.
///
/// # Errors
///
/// [`Contradiction`] if the file states another architecture.
pub fn reconcile_pe(
    architecture: Architecture,
    f: &FileFacts,
) -> Result<Fact<Architecture>, Contradiction> {
    one(
        FactKind::Architecture,
        architecture,
        f.architecture,
        Architecture::as_str,
    )
}

#[cfg(test)]
mod tests {
    use usgp_proto::facts::FactSource;

    use super::*;
    use crate::wim::xml::XmlLeaf;

    fn image(leaves: &[(&str, &str)]) -> WimXmlImage {
        WimXmlImage {
            index: 1,
            name: "Windows 11 Enterprise".into(),
            description: "Windows 11 Enterprise x64 LTSC arm64".into(),
            total_bytes: None,
            elements: leaves
                .iter()
                .map(|(p, t)| XmlLeaf {
                    path: (*p).into(),
                    text: (*t).into(),
                })
                .collect(),
        }
    }

    /// A test-only table; its paths are invented and document nothing.
    const TEST_TABLE: FactTable = FactTable::new(&[
        FactRule {
            path: "TEST/ARCH",
            text: "9",
            value: FactValue::Architecture(Architecture::X64),
        },
        FactRule {
            path: "TEST/ARCH",
            text: "12",
            value: FactValue::Architecture(Architecture::Arm64),
        },
        FactRule {
            path: "TEST/EDITION",
            text: "Enterprise",
            value: FactValue::Edition(Edition::Enterprise),
        },
    ]);

    const DECL: Declared = Declared {
        release: Release::Windows11,
        edition: Edition::Enterprise,
        architecture: Architecture::X64,
    };

    #[test]
    fn empty_table_all_declared() {
        assert!(FactTable::DOCUMENTED.rules().is_empty());
        let f = read_file_facts(&image(&[("TEST/ARCH", "9")]), &FactTable::DOCUMENTED);
        let facts = reconcile(&DECL, &f).unwrap();
        assert_eq!(facts.release, Fact::declared(Release::Windows11));
        assert_eq!(facts.edition.source, FactSource::Declared);
        assert_eq!(facts.architecture.source, FactSource::Declared);
    }

    #[test]
    fn no_name_inference() {
        // NAME and DESCRIPTION say "LTSC arm64"; nothing reads them, even
        // with a test table.
        let f = read_file_facts(&image(&[]), &TEST_TABLE);
        assert_eq!(f.edition, FileFact::NotStated);
        assert_eq!(f.architecture, FileFact::NotStated);
        let d = Declared {
            edition: Edition::Pro,
            ..DECL
        };
        assert_eq!(
            reconcile(&d, &f).unwrap().edition,
            Fact::declared(Edition::Pro)
        );
    }

    #[test]
    fn agreement_is_verified() {
        let f = read_file_facts(
            &image(&[("TEST/ARCH", "9"), ("TEST/EDITION", "Enterprise")]),
            &TEST_TABLE,
        );
        let facts = reconcile(&DECL, &f).unwrap();
        assert_eq!(facts.architecture, Fact::verified(Architecture::X64));
        assert_eq!(facts.edition, Fact::verified(Edition::Enterprise));
        assert_eq!(facts.release, Fact::declared(Release::Windows11));
    }

    #[test]
    fn contradiction_refused() {
        let f = read_file_facts(&image(&[("TEST/ARCH", "12")]), &TEST_TABLE);
        let c = reconcile(&DECL, &f).unwrap_err();
        assert_eq!(c.fact, FactKind::Architecture);
        assert_eq!(c.declared, "x64");
        assert_eq!(c.file, "arm64");
        assert_eq!(
            c.reason_code().as_str(),
            "declaration_contradicts_file:architecture"
        );
        assert!(c.operator_message().contains("x64"));
        // Exact text only: " 9" does not match "9".
        let f = read_file_facts(&image(&[("TEST/ARCH", " 9")]), &TEST_TABLE);
        assert_eq!(f.architecture, FileFact::NotStated);
    }

    #[test]
    fn inconsistent_file_refused() {
        let f = read_file_facts(
            &image(&[("TEST/ARCH", "9"), ("TEST/ARCH", "12")]),
            &TEST_TABLE,
        );
        assert_eq!(f.architecture, FileFact::Inconsistent);
        assert_eq!(reconcile(&DECL, &f).unwrap_err().file, "inconsistent");
    }

    #[test]
    fn pe_contradiction() {
        let f = read_file_facts(&image(&[("TEST/ARCH", "12")]), &TEST_TABLE);
        let c = reconcile_pe(Architecture::X64, &f).unwrap_err();
        assert_eq!(c.fact, FactKind::Architecture);
        let f = read_file_facts(&image(&[]), &FactTable::DOCUMENTED);
        assert_eq!(
            reconcile_pe(Architecture::X64, &f),
            Ok(Fact::declared(Architecture::X64))
        );
    }
}
