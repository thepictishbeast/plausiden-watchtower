//! Parse PlausiDen structured-log lines into typed `LogEvent` records.
//!
//! Source format (from `server/logger.ts`):
//!
//! ```text
//! [3:55:50 PM] [WARN] [security] chain=registration rid=abc123 step=POST /api/register 5/8 REJECT duplicate piiHash
//! ```
//!
//! The parser is regex-based. We do NOT require all fields; lines from
//! older code paths that don't carry `chain=` / `rid=` / `step=` still
//! parse — they just produce events with those fields set to `None`.
//!
//! Lines that don't match the bracket prefix at all are returned as
//! `LogEvent::Unstructured` so the watchtower can still alert on raw
//! `panic`/`segfault`/`oom-killer` lines from sidecars that don't use
//! the canonical logger.

use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
    Other(String),
}

impl Level {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_uppercase().as_str() {
            "DEBUG" => Level::Debug,
            "INFO" => Level::Info,
            "WARN" | "WARNING" => Level::Warn,
            "ERROR" | "ERR" => Level::Error,
            "FATAL" | "CRITICAL" | "CRIT" => Level::Fatal,
            other => Level::Other(other.to_string()),
        }
    }

    /// Strict ordering for threshold rules.
    pub fn rank(&self) -> u8 {
        match self {
            Level::Debug => 0,
            Level::Info => 1,
            Level::Warn => 2,
            Level::Error => 3,
            Level::Fatal => 4,
            Level::Other(_) => 1, // unknown levels treated as info
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredEvent {
    pub level: Level,
    pub source: String,
    pub chain: Option<String>,
    pub rid: Option<String>,
    pub step: Option<String>,
    pub message: String,
    pub raw: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogEvent {
    Structured(StructuredEvent),
    Unstructured { raw: String },
}

impl LogEvent {
    pub fn raw(&self) -> &str {
        match self {
            LogEvent::Structured(e) => &e.raw,
            LogEvent::Unstructured { raw } => raw,
        }
    }
}

// `[H:MM:SS AM/PM]` or `[HH:MM:SS]` — we don't keep the timestamp from the
// log line itself (the journal already supplies wall-clock time), but we
// need to *consume* it so the rest of the parser is anchored.
static PREFIX: OnceLock<Regex> = OnceLock::new();
static FIELD_CHAIN: OnceLock<Regex> = OnceLock::new();
static FIELD_RID: OnceLock<Regex> = OnceLock::new();
static FIELD_STEP: OnceLock<Regex> = OnceLock::new();

fn prefix() -> &'static Regex {
    PREFIX.get_or_init(|| {
        // [<time>] [<LEVEL>] [<source>] <message>
        // <time> matches both 12h ("3:55:50 PM") and 24h ("15:55:50") forms
        Regex::new(r"^\[(?P<time>[^\]]+)\]\s+\[(?P<level>[A-Za-z]+)\]\s+\[(?P<source>[^\]]+)\]\s*(?P<rest>.*)$")
            .expect("prefix regex compiles")
    })
}

fn field_chain() -> &'static Regex {
    FIELD_CHAIN.get_or_init(|| Regex::new(r"\bchain=(?P<v>[A-Za-z0-9_\-]+)").unwrap())
}

fn field_rid() -> &'static Regex {
    FIELD_RID.get_or_init(|| Regex::new(r"\brid=(?P<v>[A-Za-z0-9_\-]+)").unwrap())
}

fn field_step() -> &'static Regex {
    FIELD_STEP.get_or_init(|| {
        // step=POST /api/register 5/8 REJECT duplicate piiHash
        // Capture up to and including the "N/M" fragment. Anything after that
        // is free-form so we don't try to grammar it.
        Regex::new(r"\bstep=(?P<v>[^\s]+(?:\s+[^\s]+)*?\s+\d+/\d+)").unwrap()
    })
}

/// Parse a single line.
///
/// Returns `LogEvent::Structured` when the bracket prefix is present;
/// `LogEvent::Unstructured` otherwise. Never panics, never returns an
/// error — bad lines fall through to `Unstructured`.
pub fn parse_line(line: &str) -> LogEvent {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return LogEvent::Unstructured {
            raw: line.to_string(),
        };
    }

    let Some(caps) = prefix().captures(trimmed) else {
        return LogEvent::Unstructured {
            raw: line.to_string(),
        };
    };

    let level = Level::parse(caps.name("level").map(|m| m.as_str()).unwrap_or(""));
    let source = caps
        .name("source")
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();
    let rest = caps
        .name("rest")
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();

    let chain = field_chain()
        .captures(&rest)
        .and_then(|c| c.name("v"))
        .map(|m| m.as_str().to_string());
    let rid = field_rid()
        .captures(&rest)
        .and_then(|c| c.name("v"))
        .map(|m| m.as_str().to_string());
    let step = field_step()
        .captures(&rest)
        .and_then(|c| c.name("v"))
        .map(|m| m.as_str().to_string());

    LogEvent::Structured(StructuredEvent {
        level,
        source,
        chain,
        rid,
        step,
        message: rest,
        raw: line.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn structured(line: &str) -> StructuredEvent {
        match parse_line(line) {
            LogEvent::Structured(e) => e,
            LogEvent::Unstructured { raw } => panic!("expected structured, got: {raw}"),
        }
    }

    #[test]
    fn parses_minimal_info_line() {
        let line = "[3:55:50 PM] [INFO] [startup] Server listening on 5000";
        let e = structured(line);
        assert_eq!(e.level, Level::Info);
        assert_eq!(e.source, "startup");
        assert_eq!(e.chain, None);
        assert_eq!(e.rid, None);
        assert_eq!(e.step, None);
        assert!(e.message.contains("Server listening"));
    }

    #[test]
    fn parses_full_chain_line() {
        let line = "[3:55:50 PM] [WARN] [security] chain=registration rid=abc123 step=POST /api/register 5/8 REJECT duplicate piiHash";
        let e = structured(line);
        assert_eq!(e.level, Level::Warn);
        assert_eq!(e.source, "security");
        assert_eq!(e.chain.as_deref(), Some("registration"));
        assert_eq!(e.rid.as_deref(), Some("abc123"));
        assert!(e.step.as_deref().unwrap().ends_with("5/8"));
    }

    #[test]
    fn parses_24h_timestamp() {
        let line = "[15:55:50] [ERROR] [database] connection refused";
        let e = structured(line);
        assert_eq!(e.level, Level::Error);
        assert_eq!(e.source, "database");
    }

    #[test]
    fn unknown_level_falls_through_to_other() {
        let line = "[3:55:50 PM] [WTF] [security] something weird";
        let e = structured(line);
        match e.level {
            Level::Other(s) => assert_eq!(s, "WTF"),
            _ => panic!("expected Other"),
        }
    }

    #[test]
    fn unstructured_when_no_bracket_prefix() {
        let line = "panic: kernel/oom-killer something something";
        match parse_line(line) {
            LogEvent::Unstructured { raw } => assert_eq!(raw, line),
            LogEvent::Structured(e) => panic!("expected unstructured, got: {e:?}"),
        }
    }

    #[test]
    fn empty_line_is_unstructured() {
        match parse_line("") {
            LogEvent::Unstructured { .. } => {}
            _ => panic!("expected unstructured"),
        }
    }

    #[test]
    fn level_rank_orders_correctly() {
        assert!(Level::Fatal.rank() > Level::Error.rank());
        assert!(Level::Error.rank() > Level::Warn.rank());
        assert!(Level::Warn.rank() > Level::Info.rank());
        assert!(Level::Info.rank() > Level::Debug.rank());
    }

    #[test]
    fn does_not_panic_on_pathological_input() {
        // Newlines, NULs, very long lines must not crash.
        for input in &[
            "[3:55:50 PM] [WARN] [security] \0\0\0",
            "[3:55:50 PM] [WARN] [security]",
            &"x".repeat(100_000),
            "][][][][][",
        ] {
            let _ = parse_line(input);
        }
    }

    #[test]
    fn parses_chain_without_rid_or_step() {
        // Older code might emit chain= without the full triple.
        let line = "[3:55:50 PM] [INFO] [registration] chain=registration arrived";
        let e = structured(line);
        assert_eq!(e.chain.as_deref(), Some("registration"));
        assert_eq!(e.rid, None);
        assert_eq!(e.step, None);
    }

    #[test]
    fn level_aliases_are_normalized() {
        assert_eq!(Level::parse("warning"), Level::Warn);
        assert_eq!(Level::parse("err"), Level::Error);
        assert_eq!(Level::parse("CRIT"), Level::Fatal);
        assert_eq!(Level::parse("CRITICAL"), Level::Fatal);
    }
}
