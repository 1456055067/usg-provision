//! Template lint (plan section 1.6, "Lint" and "Value consistency").

// COMPLIANCE MAPPING:
// - NIST 800-53: IA-5(7) (No Embedded Unencrypted Static Authenticators) -
//   settings that can carry a password, credential or product key are
//   refused; SI-10 (Information Input Validation) - no value is
//   substituted into a command line; CM-6 (Configuration Settings)
// - SPEC: specs/configuration.md#REQ-CFG-002, #REQ-CFG-005,
//   #REQ-CFG-007, #REQ-CFG-010
// - SPEC: specs/standards/unattend.md §3.3, §4 (clear-text secrets)
// - Decisions 0024, 0025

use std::collections::BTreeSet;

use super::values::{ValueError, check_carried, check_computer_name, check_time_zone};
use super::{Element, Node, Segment, Template, collect_refs};

/// Settings refused anywhere, by local name: each can carry a password,
/// credential or product key (`unattend.md` §3.3, §4). `Key` under
/// `ProductKey` and `Password` under `DomainAccounts`/`LocalAccounts`
/// are covered by the parent or by `Password`.
const SECRET_BEARING: &[&str] = &[
    "Password",
    "AdministratorPassword",
    "Credentials",
    "ProductKey",
    "AutoLogon",
];

/// Command settings that must not hold a reference.
const COMMANDS: &[&str] = &["RunSynchronous", "RunAsynchronous", "FirstLogonCommands"];

/// Where the package's computer name comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComputerNameSource {
    /// One literal name for the package.
    Value(String),
    /// Per device (`device.computer_name`, set by an operator).
    PerDevice,
}

/// The package values a template is checked against. None are secrets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackageValues {
    /// Computer name, if the package sets one.
    pub computer_name: Option<ComputerNameSource>,
    /// Time zone, if set.
    pub time_zone: Option<String>,
    /// Domain, if set.
    pub domain: Option<String>,
    /// Machine OU, if set.
    pub machine_ou: Option<String>,
}

/// One reason a package is not ready. Paths name elements only, never
/// text or attribute values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LintFinding {
    /// `secret_bearing_setting{path}`.
    SecretBearingSetting {
        /// Element path.
        path: String,
    },
    /// A reference inside a command setting.
    ReferenceInCommand {
        /// Element path of the command setting.
        path: String,
    },
    /// `unknown_reference{name}`.
    UnknownReference {
        /// Reference name.
        name: String,
    },
    /// `value_not_referenced{name}`.
    ValueNotReferenced {
        /// Package value name.
        name: &'static str,
    },
    /// A literal package value failed its check.
    InvalidValue {
        /// Package value name.
        name: &'static str,
        /// The failed check.
        reason: ValueError,
    },
}

impl Template {
    /// Checks the template against the package values. An empty result
    /// means the configuration is complete.
    #[must_use]
    pub fn lint(&self, values: &PackageValues) -> Vec<LintFinding> {
        let mut out = Vec::new();
        let mut found = Found::default();
        walk(&self.root, &mut Vec::new(), None, &mut out, &mut found);

        let mut refs = BTreeSet::new();
        collect_refs(&self.root, &mut refs);
        for name in refs {
            if !known(&name, values) {
                out.push(LintFinding::UnknownReference { name });
            }
        }

        if let Some(src) = &values.computer_name {
            if let ComputerNameSource::Value(v) = src
                && let Err(reason) = check_computer_name(v)
            {
                out.push(LintFinding::InvalidValue {
                    name: "computer_name",
                    reason,
                });
            }
            if !found.computer_name {
                out.push(LintFinding::ValueNotReferenced {
                    name: "computer_name",
                });
            }
        }
        if let Some(tz) = &values.time_zone {
            if let Err(reason) = check_time_zone(tz) {
                out.push(LintFinding::InvalidValue {
                    name: "time_zone",
                    reason,
                });
            }
            if !found.time_zone {
                out.push(LintFinding::ValueNotReferenced { name: "time_zone" });
            }
        }
        for (name, v) in [
            ("domain", &values.domain),
            ("machine_ou", &values.machine_ou),
        ] {
            if let Some(v) = v
                && let Err(reason) = check_carried(v)
            {
                out.push(LintFinding::InvalidValue { name, reason });
            }
        }
        out
    }
}

/// A package name is known only if the package sets it; `device.*` names
/// are resolved per device at render.
fn known(name: &str, v: &PackageValues) -> bool {
    match name {
        "computer_name" => matches!(v.computer_name, Some(ComputerNameSource::Value(_))),
        "time_zone" => v.time_zone.is_some(),
        "domain" => v.domain.is_some(),
        "machine_ou" => v.machine_ou.is_some(),
        _ => name.strip_prefix("device.").is_some_and(|k| !k.is_empty()),
    }
}

#[derive(Default)]
struct Found {
    computer_name: bool,
    time_zone: bool,
}

fn walk(
    e: &Element,
    path: &mut Vec<String>,
    pass: Option<&str>,
    out: &mut Vec<LintFinding>,
    found: &mut Found,
) {
    let pass_here = if e.local == "settings" {
        e.literal_attr("pass")
    } else {
        None
    };
    let label = match &pass_here {
        Some(p) => format!("settings[{p}]"),
        None => e.local.clone(),
    };
    path.push(label);
    let pass = pass_here.as_deref().or(pass);

    if SECRET_BEARING.contains(&e.local.as_str()) {
        out.push(LintFinding::SecretBearingSetting {
            path: path.join("/"),
        });
    } else if COMMANDS.contains(&e.local.as_str()) && has_ref(e) {
        out.push(LintFinding::ReferenceInCommand {
            path: path.join("/"),
        });
    } else {
        if e.local == "ComputerName"
            && pass == Some("specialize")
            && sole_ref(e).is_some_and(|n| n == "computer_name" || n == "device.computer_name")
        {
            found.computer_name = true;
        }
        if e.local == "TimeZone"
            && matches!(pass, Some("specialize" | "oobeSystem"))
            && sole_ref(e) == Some("time_zone")
        {
            found.time_zone = true;
        }
        for c in &e.children {
            if let Node::Element(child) = c {
                walk(child, path, pass, out, found);
            }
        }
    }
    path.pop();
}

fn has_ref(e: &Element) -> bool {
    let mut set = BTreeSet::new();
    collect_refs(e, &mut set);
    !set.is_empty()
}

/// The single reference that is an element's whole text (surrounding
/// whitespace allowed), if it has no child elements.
fn sole_ref(e: &Element) -> Option<&str> {
    let mut name = None;
    for c in &e.children {
        let Node::Text(segs) = c else { return None };
        for s in segs {
            match s {
                Segment::Literal(t) if t.trim().is_empty() => {}
                Segment::Ref(n) if name.is_none() => name = Some(n.as_str()),
                _ => return None,
            }
        }
    }
    name
}
