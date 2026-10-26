//! Process-wide tracing subscriber.
//!
//! Output goes to stdout with UTC RFC 3339 timestamps and no ANSI colour.
//! [`LogFormat::Json`] writes one JSON object per line with the event
//! fields at the top level. The configured level applies to every target
//! except [`crate::event::AUDIT_TARGET`], which is always kept (AU-12).

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-3 (Content of Audit Records) - UTC timestamps on every
//   record.
// - NIST 800-53: AU-8 (Time Stamps) - RFC 3339 UTC from the system clock.
// - NIST 800-53: AU-12 (Audit Record Generation) - audit target is never
//   filtered by the log level.
// - RFC 3339 §5.6 - timestamp format.

// POAM: AU-5 (Response to Audit Logging Process Failures) - write errors
// on stdout are dropped by the fmt layer; the process keeps running with
// no record and no alert. M2's usgp-audit store handles write failure;
// until then deployment must run the relay under a persistent, monitored
// journal (docs/operations/relay.md).

use std::io;

use tracing::Subscriber;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt as _;

pub use tracing::Level;

use crate::event::AUDIT_TARGET;

/// Output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum LogFormat {
    /// One JSON object per line (the service default).
    #[default]
    Json,
    /// Human-readable single lines, no colour (for interactive tools).
    Text,
}

/// Telemetry setup errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TelemetryError {
    /// A global subscriber was already installed.
    #[error("a tracing subscriber is already installed")]
    AlreadyInitialised,
    /// The level text is not one of `error`, `warn`, `info`, `debug`.
    #[error("log level must be one of error, warn, info, debug")]
    InvalidLevel,
}

/// Parses a configured log level: exactly `error`, `warn`, `info` or
/// `debug` (lowercase; relay config `log.level`). `trace` is not offered.
///
/// # Errors
///
/// [`TelemetryError::InvalidLevel`] for any other text. The input is not
/// echoed.
pub fn parse_level(text: &str) -> Result<Level, TelemetryError> {
    match text {
        "error" => Ok(Level::ERROR),
        "warn" => Ok(Level::WARN),
        "info" => Ok(Level::INFO),
        "debug" => Ok(Level::DEBUG),
        _ => Err(TelemetryError::InvalidLevel),
    }
}

/// Installs the global subscriber, writing to stdout.
///
/// # Errors
///
/// [`TelemetryError::AlreadyInitialised`] if a global subscriber exists.
pub fn init(level: Level, format: LogFormat) -> Result<(), TelemetryError> {
    let sub = build(level, format, io::stdout);
    tracing::subscriber::set_global_default(sub).map_err(|_| TelemetryError::AlreadyInitialised)
}

/// Builds the subscriber `init` installs, with any writer (used by tests).
pub(crate) fn build<W>(
    level: Level,
    format: LogFormat,
    writer: W,
) -> Box<dyn Subscriber + Send + Sync>
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let filter = Targets::new()
        .with_default(LevelFilter::from_level(level))
        .with_target(AUDIT_TARGET, LevelFilter::INFO);
    let base = tracing_subscriber::fmt()
        .with_writer(writer)
        .with_ansi(false)
        .with_max_level(LevelFilter::TRACE);
    match format {
        LogFormat::Json => Box::new(
            base.json()
                .flatten_event(true)
                .with_current_span(false)
                .with_span_list(false)
                .finish()
                .with(filter),
        ),
        LogFormat::Text => Box::new(base.finish().with(filter)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{AuditEvent, Outcome, emit};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Buf {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Buf {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    fn capture(level: Level, format: LogFormat, f: impl FnOnce()) -> String {
        let buf = Buf::default();
        let w = buf.clone();
        let sub = build(level, format, move || w.clone());
        tracing::subscriber::with_default(sub, f);
        buf.text()
    }

    #[test]
    fn level_parse() {
        assert_eq!(parse_level("error"), Ok(Level::ERROR));
        assert_eq!(parse_level("warn"), Ok(Level::WARN));
        assert_eq!(parse_level("info"), Ok(Level::INFO));
        assert_eq!(parse_level("debug"), Ok(Level::DEBUG));
        for bad in ["", "INFO", "trace", "warning", " info", "info\n"] {
            assert_eq!(
                parse_level(bad),
                Err(TelemetryError::InvalidLevel),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn json_audit_line_has_au3_fields() {
        let detail = [("file", "a\"b".to_owned())];
        let out = capture(Level::INFO, LogFormat::Json, || {
            emit(&AuditEvent {
                interface: Some("eth1"),
                peer: Some("192.0.2.7:68".parse().unwrap()),
                claimed_mac: Some("52:54:00:12:34:56".to_owned()),
                detail: &detail,
                ..AuditEvent::new("boot.file.verified", Outcome::Success, "usgp-relay")
            });
        });
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 1, "{out}");
        let line = lines.first().copied().unwrap_or_default();
        assert!(line.starts_with("{\"timestamp\":\""), "{line}");
        for needle in [
            r#""target":"audit""#,
            r#""event":"boot.file.verified""#,
            r#""outcome":"success""#,
            r#""component":"usgp-relay""#,
            r#""interface":"eth1""#,
            r#""peer":"192.0.2.7:68""#,
            r#""claimed_mac":"52:54:00:12:34:56""#,
            r#""detail":"{\"file\":\"a\\\"b\"}""#,
        ] {
            assert!(line.contains(needle), "missing {needle} in {line}");
        }
        // Absent optional fields are omitted, not written as null.
        assert!(!line.contains("claimed_guid"), "{line}");
        assert!(!line.contains("local_addr"), "{line}");
        assert!(!line.contains('\u{1b}'), "ANSI escape in {line}");
    }

    #[test]
    fn timestamp_is_utc_rfc3339() {
        let out = capture(Level::INFO, LogFormat::Json, || {
            emit(&AuditEvent::new("t", Outcome::Failure, "c"));
        });
        let ts = out
            .split("\"timestamp\":\"")
            .nth(1)
            .and_then(|r| r.split('"').next())
            .unwrap();
        // YYYY-MM-DDTHH:MM:SS[.frac]Z
        let b = ts.as_bytes();
        assert!(ts.ends_with('Z'), "{ts}");
        assert!(b.len() >= 20, "{ts}");
        assert_eq!(b.get(4), Some(&b'-'));
        assert_eq!(b.get(7), Some(&b'-'));
        assert_eq!(b.get(10), Some(&b'T'));
        assert_eq!(b.get(13), Some(&b':'));
        assert_eq!(b.get(16), Some(&b':'));
    }

    #[test]
    fn audit_survives_error_level_but_info_does_not() {
        let out = capture(Level::ERROR, LogFormat::Json, || {
            tracing::info!(target: "usgp_relay", "ordinary info");
            tracing::error!(target: "usgp_relay", "ordinary error");
            emit(&AuditEvent::new(
                "relay.start",
                Outcome::Success,
                "usgp-relay",
            ));
        });
        assert!(!out.contains("ordinary info"), "{out}");
        assert!(out.contains("ordinary error"), "{out}");
        assert!(out.contains("relay.start"), "{out}");
    }

    #[test]
    fn debug_level_passes_debug() {
        let out = capture(Level::DEBUG, LogFormat::Json, || {
            tracing::debug!(target: "x", "dbg line");
            tracing::trace!(target: "x", "trace line");
        });
        assert!(out.contains("dbg line"));
        assert!(!out.contains("trace line"));
    }

    #[test]
    fn text_format_no_ansi_and_escapes_newlines() {
        let out = capture(Level::INFO, LogFormat::Text, || {
            emit(&AuditEvent {
                claimed_guid: Some("x\ny".to_owned()),
                ..AuditEvent::new("relay.stop", Outcome::Success, "usgp-relay")
            });
        });
        assert_eq!(out.lines().count(), 1, "{out}");
        assert!(out.contains("relay.stop"));
        assert!(!out.contains('\u{1b}'));
    }
}
