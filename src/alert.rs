//! Alert sinks. The trait is the contract; implementations land in #316
//! (ntfy + email). For #315 we ship the trait, a `Logger` sink that just
//! writes to tracing (so the daemon is testable end-to-end), and a
//! `MultiSink` that fans out to N sinks with per-sink failure isolation.

use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;

use crate::classify::Alert;

#[derive(Debug, Error)]
pub enum SinkError {
    #[error("sink failed: {0}")]
    Failed(String),
}

#[async_trait]
pub trait AlertSink: Send + Sync {
    /// Sink identifier for logging.
    fn name(&self) -> &str;

    /// Deliver the alert. Idempotent on retry — sink is responsible for
    /// any deduplication beyond the classifier's own cooldown.
    async fn dispatch(&self, alert: &Alert) -> Result<(), SinkError>;
}

/// Default sink — writes the alert as a structured tracing event.
/// Always-on so the daemon never silently drops alerts when no other
/// sink is configured.
pub struct LoggerSink;

#[async_trait]
impl AlertSink for LoggerSink {
    fn name(&self) -> &str {
        "logger"
    }

    async fn dispatch(&self, alert: &Alert) -> Result<(), SinkError> {
        let json = serde_json::to_string(&AlertOut::from(alert))
            .map_err(|e| SinkError::Failed(e.to_string()))?;
        tracing::warn!(alert = %json, "watchtower alert fired");
        Ok(())
    }
}

/// Fan-out sink. A failure in one inner sink is logged but does not
/// suppress dispatch to the others — partial delivery is preferred to
/// silent drop.
pub struct MultiSink {
    sinks: Vec<Box<dyn AlertSink>>,
}

impl MultiSink {
    pub fn new(sinks: Vec<Box<dyn AlertSink>>) -> Self {
        Self { sinks }
    }

    pub fn with(mut self, sink: Box<dyn AlertSink>) -> Self {
        self.sinks.push(sink);
        self
    }

    pub fn len(&self) -> usize {
        self.sinks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sinks.is_empty()
    }
}

#[async_trait]
impl AlertSink for MultiSink {
    fn name(&self) -> &str {
        "multi"
    }

    async fn dispatch(&self, alert: &Alert) -> Result<(), SinkError> {
        let mut failures = 0;
        for sink in &self.sinks {
            if let Err(e) = sink.dispatch(alert).await {
                tracing::error!(sink = sink.name(), error = %e, "sink dispatch failed");
                failures += 1;
            }
        }
        if failures == self.sinks.len() && !self.sinks.is_empty() {
            Err(SinkError::Failed(format!("all {failures} sinks failed")))
        } else {
            Ok(())
        }
    }
}

/// Wire-format-friendly serialization of an Alert (raw struct includes
/// chrono Duration etc that don't serialize cleanly).
#[derive(Serialize)]
struct AlertOut<'a> {
    severity: &'a str,
    rule: &'a str,
    key: &'a str,
    count: usize,
    window_secs: i64,
    fired_at_rfc3339: String,
    sample_chain: Option<&'a str>,
    sample_rid: Option<&'a str>,
    sample_step: Option<&'a str>,
    sample_message: Option<&'a str>,
}

impl<'a> From<&'a Alert> for AlertOut<'a> {
    fn from(a: &'a Alert) -> Self {
        Self {
            severity: match a.severity {
                crate::classify::Severity::Info => "info",
                crate::classify::Severity::Warn => "warn",
                crate::classify::Severity::Page => "page",
            },
            rule: &a.rule,
            key: &a.key,
            count: a.count,
            window_secs: a.window_secs,
            fired_at_rfc3339: a.fired_at.to_rfc3339(),
            sample_chain: a.sample_event.as_ref().and_then(|e| e.chain.as_deref()),
            sample_rid: a.sample_event.as_ref().and_then(|e| e.rid.as_deref()),
            sample_step: a.sample_event.as_ref().and_then(|e| e.step.as_deref()),
            sample_message: a.sample_event.as_ref().map(|e| e.message.as_str()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::{Alert, Severity};
    use chrono::Utc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn sample_alert() -> Alert {
        Alert {
            severity: Severity::Page,
            rule: "fatal_any".into(),
            key: "any".into(),
            count: 1,
            window_secs: 86_400,
            sample_event: None,
            fired_at: Utc::now(),
        }
    }

    struct CountingSink {
        name_: String,
        count: Arc<AtomicUsize>,
        fail: bool,
    }

    #[async_trait]
    impl AlertSink for CountingSink {
        fn name(&self) -> &str {
            &self.name_
        }
        async fn dispatch(&self, _alert: &Alert) -> Result<(), SinkError> {
            self.count.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                Err(SinkError::Failed("synthetic".into()))
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn logger_sink_succeeds() {
        let sink = LoggerSink;
        sink.dispatch(&sample_alert()).await.unwrap();
    }

    #[tokio::test]
    async fn multisink_dispatches_to_all() {
        let count = Arc::new(AtomicUsize::new(0));
        let sinks: Vec<Box<dyn AlertSink>> = vec![
            Box::new(CountingSink { name_: "a".into(), count: count.clone(), fail: false }),
            Box::new(CountingSink { name_: "b".into(), count: count.clone(), fail: false }),
        ];
        let multi = MultiSink::new(sinks);
        multi.dispatch(&sample_alert()).await.unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn multisink_partial_failure_is_ok() {
        let count = Arc::new(AtomicUsize::new(0));
        let sinks: Vec<Box<dyn AlertSink>> = vec![
            Box::new(CountingSink { name_: "ok".into(), count: count.clone(), fail: false }),
            Box::new(CountingSink { name_: "fail".into(), count: count.clone(), fail: true }),
        ];
        let multi = MultiSink::new(sinks);
        // 1 of 2 fails — overall result is Ok (partial delivery preferred).
        multi.dispatch(&sample_alert()).await.unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn multisink_total_failure_returns_err() {
        let count = Arc::new(AtomicUsize::new(0));
        let sinks: Vec<Box<dyn AlertSink>> = vec![
            Box::new(CountingSink { name_: "a".into(), count: count.clone(), fail: true }),
            Box::new(CountingSink { name_: "b".into(), count: count.clone(), fail: true }),
        ];
        let multi = MultiSink::new(sinks);
        let res = multi.dispatch(&sample_alert()).await;
        assert!(res.is_err());
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn empty_multisink_is_ok() {
        let multi = MultiSink::new(Vec::new());
        // No sinks → trivially Ok. The daemon enforces "at least one"
        // configured at startup; the type itself does not.
        multi.dispatch(&sample_alert()).await.unwrap();
        assert!(multi.is_empty());
    }
}
