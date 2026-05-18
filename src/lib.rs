//! # plausiden-watchtower
//!
//! Tails per-chain structured logs from the PlausiDen / Sacred Vote
//! service stack and dispatches alerts when classification rules fire.
//!
//! ## Modules
//!
//! - [`parse`] — turn raw log lines into typed `LogEvent`s
//! - [`classify`] — sliding-window threshold engine that produces `Alert`s
//! - [`alert`] — sink trait and built-in sinks (logger, multi)
//! - [`journal`] — live journalctl reader (only with `journal` feature)
//!
//! ## Usage
//!
//! ```no_run
//! use plausiden_watchtower::{
//!     classify::Classifier,
//!     parse::parse_line,
//!     alert::{AlertSink, LoggerSink},
//! };
//! use chrono::Utc;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let mut classifier = Classifier::new();
//! let sink = LoggerSink;
//!
//! let line = "[3:55:50 PM] [FATAL] [storage] postgres unreachable";
//! let event = parse_line(line);
//! for alert in classifier.ingest(&event, Utc::now()) {
//!     sink.dispatch(&alert).await?;
//! }
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

pub mod alert;
pub mod classify;
pub mod parse;
pub mod self_monitor;

#[cfg(feature = "journal")]
pub mod journal;

pub use alert::{AlertSink, LoggerSink, MultiSink, SinkError};
pub use classify::{Alert, Classifier, Severity};
pub use parse::{parse_line, Level, LogEvent, StructuredEvent};
pub use self_monitor::{HeartbeatConfig, HeartbeatCounter};
