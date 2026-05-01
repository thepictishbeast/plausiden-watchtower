//! ntfy push sink. Delivers alerts to the user's phone via the
//! self-hosted ntfy server documented in `reference_messaging_infra.md`.
//!
//! Wire format:
//!   POST {url}/{topic}
//!   Authorization: Bearer {token}
//!   Title: <severity-prefix> watchtower: <rule>
//!   Priority: <urgent|high|default>
//!   Tags: rotating_light,<chain>
//!   <body — short summary + truncated sample line>
//!
//! Default rate-limit: 10 pushes/minute (token bucket). The classifier
//! already cools down per (rule,key); this is the second guard in case
//! rules ever loosen.

use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::Client;

use crate::alert::rate_limit::TokenBucket;
use crate::alert::{AlertSink, SinkError};
use crate::classify::{Alert, Severity};

const DEFAULT_TIMEOUT_SECS: u64 = 5;
const DEFAULT_RATE_PER_MIN: u32 = 10;

/// ntfy sink. Push messages over HTTP to an ntfy server.
pub struct NtfySink {
    url: String,
    topic: String,
    token: Option<String>,
    client: Client,
    bucket: Mutex<TokenBucket>,
}

#[derive(Debug, thiserror::Error)]
pub enum NtfyConfigError {
    #[error("invalid ntfy URL: {0}")]
    InvalidUrl(String),
    #[error("HTTP client build failed: {0}")]
    ClientBuild(String),
}

impl NtfySink {
    /// Build a sink with explicit config. Prefer `from_env()` in
    /// production; the explicit constructor is for tests + a future
    /// programmatic config loader.
    pub fn new(
        url: impl Into<String>,
        topic: impl Into<String>,
        token: Option<String>,
        rate_per_min: u32,
    ) -> Result<Self, NtfyConfigError> {
        let url = url.into();
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(NtfyConfigError::InvalidUrl(url));
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .build()
            .map_err(|e| NtfyConfigError::ClientBuild(e.to_string()))?;
        Ok(Self {
            url: url.trim_end_matches('/').to_string(),
            topic: topic.into(),
            token,
            client,
            bucket: Mutex::new(TokenBucket::new(rate_per_min, Duration::from_secs(60))),
        })
    }

    /// Build a sink from environment. Returns `Ok(None)` if the
    /// minimum required vars (`NTFY_URL` + `WATCHTOWER_NTFY_TOPIC`) are
    /// absent — caller decides whether absence is fatal.
    pub fn from_env() -> Result<Option<Self>, NtfyConfigError> {
        Self::from_env_with(|k| std::env::var(k).ok())
    }

    /// Same as [`from_env`] but with an injectable env-lookup closure
    /// so tests can stay pure and avoid mutating real process env.
    pub fn from_env_with(
        getenv: impl Fn(&str) -> Option<String>,
    ) -> Result<Option<Self>, NtfyConfigError> {
        let Some(url) = getenv("NTFY_URL") else {
            return Ok(None);
        };
        let topic =
            getenv("WATCHTOWER_NTFY_TOPIC").unwrap_or_else(|| "sacredvote-watchtower".to_string());
        if topic.is_empty() {
            return Ok(None);
        }
        let token = getenv("NTFY_TOKEN").filter(|s| !s.is_empty());
        let rate_per_min = getenv("WATCHTOWER_NTFY_RATE_PER_MIN")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(DEFAULT_RATE_PER_MIN);
        Self::new(url, topic, token, rate_per_min).map(Some)
    }

    fn priority(&self, sev: Severity) -> &'static str {
        match sev {
            Severity::Page => "urgent",
            Severity::Warn => "high",
            Severity::Info => "default",
        }
    }

    fn title_prefix(&self, sev: Severity) -> &'static str {
        match sev {
            Severity::Page => "[PAGE]",
            Severity::Warn => "[WARN]",
            Severity::Info => "[INFO]",
        }
    }

    fn body_for(&self, alert: &Alert) -> String {
        let chain = alert
            .sample_event
            .as_ref()
            .and_then(|e| e.chain.as_deref())
            .unwrap_or("-");
        let rid = alert
            .sample_event
            .as_ref()
            .and_then(|e| e.rid.as_deref())
            .unwrap_or("-");
        let sample = alert
            .sample_event
            .as_ref()
            .map(|e| {
                let m = e.message.as_str();
                if m.len() > 240 {
                    format!("{}…", &m[..240])
                } else {
                    m.to_string()
                }
            })
            .unwrap_or_else(|| "(no sample)".to_string());
        format!(
            "rule={} key={} count={} chain={} rid={}\n{}",
            alert.rule, alert.key, alert.count, chain, rid, sample
        )
    }
}

#[async_trait]
impl AlertSink for NtfySink {
    fn name(&self) -> &str {
        "ntfy"
    }

    async fn dispatch(&self, alert: &Alert) -> Result<(), SinkError> {
        // Rate-limit FIRST. We'd rather drop a duplicate than let a
        // network error obscure the bucket state.
        if !self
            .bucket
            .lock()
            .map_err(|e| SinkError::Failed(format!("rate-limit poisoned: {e}")))?
            .try_take()
        {
            tracing::warn!(
                rule = %alert.rule,
                key = %alert.key,
                "ntfy rate-limited, dropping push"
            );
            // Rate-limit drop is NOT an error — sink is healthy, just
            // throttled. Returning Ok keeps MultiSink from logging it.
            return Ok(());
        }

        let title_prefix = self.title_prefix(alert.severity);
        let priority = self.priority(alert.severity);
        let body = self.body_for(alert);
        let chain_tag = alert
            .sample_event
            .as_ref()
            .and_then(|e| e.chain.as_deref())
            .unwrap_or("unknown");

        let endpoint = format!("{}/{}", self.url, self.topic);
        let mut req = self
            .client
            .post(&endpoint)
            .header("Title", format!("{} watchtower: {}", title_prefix, alert.rule))
            .header("Priority", priority)
            .header("Tags", format!("rotating_light,{}", chain_tag))
            .body(body);
        if let Some(t) = &self.token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }

        let resp = req
            .send()
            .await
            .map_err(|e| SinkError::Failed(format!("ntfy POST failed: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(SinkError::Failed(format!(
                "ntfy returned {status}: {}",
                body.chars().take(200).collect::<String>()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::{Alert, Severity};
    use chrono::Utc;

    fn page_alert() -> Alert {
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

    #[test]
    fn rejects_non_http_url() {
        // Don't use unwrap_err — NtfySink doesn't impl Debug because
        // reqwest::Client doesn't, and forbid(unsafe_code) blocks the
        // workaround. Match directly instead.
        match NtfySink::new("ftp://example.com", "t", None, 10) {
            Err(NtfyConfigError::InvalidUrl(_)) => {}
            Err(other) => panic!("wrong error variant: {other:?}"),
            Ok(_) => panic!("expected Err for ftp:// URL"),
        }
    }

    #[test]
    fn accepts_http_and_https() {
        NtfySink::new("http://127.0.0.1:8090", "t", None, 10).unwrap();
        NtfySink::new("https://ntfy.sh", "t", None, 10).unwrap();
    }

    #[test]
    fn from_env_returns_none_when_url_unset() {
        // Use the injectable env-lookup so the test stays pure (no real
        // process-env mutation, which would race other tests and
        // requires unsafe blocks under edition 2024).
        let getenv = |_: &str| None;
        let result = NtfySink::from_env_with(getenv);
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn from_env_builds_when_url_and_topic_present() {
        let getenv = |k: &str| match k {
            "NTFY_URL" => Some("http://127.0.0.1:8090".to_string()),
            "WATCHTOWER_NTFY_TOPIC" => Some("watchtower-test".to_string()),
            "NTFY_TOKEN" => Some("tk_test".to_string()),
            _ => None,
        };
        let sink = NtfySink::from_env_with(getenv).unwrap();
        assert!(sink.is_some());
    }

    #[test]
    fn from_env_treats_empty_topic_as_disabled() {
        let getenv = |k: &str| match k {
            "NTFY_URL" => Some("http://127.0.0.1:8090".to_string()),
            "WATCHTOWER_NTFY_TOPIC" => Some(String::new()),
            _ => None,
        };
        assert!(matches!(NtfySink::from_env_with(getenv), Ok(None)));
    }

    #[test]
    fn body_truncates_long_sample() {
        let sink = NtfySink::new("http://127.0.0.1:8090", "t", None, 10).unwrap();
        let mut a = page_alert();
        let msg = "x".repeat(500);
        a.sample_event = Some(crate::parse::StructuredEvent {
            level: crate::parse::Level::Fatal,
            source: "storage".into(),
            chain: Some("CHAIN".into()),
            rid: Some("rid-1".into()),
            step: None,
            message: msg.clone(),
            raw: format!("[12:00:00] [FATAL] [storage] {msg}"),
        });
        let body = sink.body_for(&a);
        assert!(body.contains("rule=fatal_any"));
        assert!(body.contains("rid=rid-1"));
        assert!(body.ends_with('…'));
    }

    #[tokio::test]
    async fn rate_limit_drops_extra_push_silently() {
        // Capacity 1 → second dispatch should be silently dropped (Ok)
        // without ever touching the network. We point at an unreachable
        // host so any real attempt would error; the test passes if the
        // rate-limiter intercepts before the request is sent.
        let sink = NtfySink::new("http://127.0.0.1:1", "t", None, 1).unwrap();
        // First call WILL try to hit 127.0.0.1:1 and fail — that's fine,
        // we just want to consume the token. We expect Err.
        let _ = sink.dispatch(&page_alert()).await;
        // Second call should be rate-limited → Ok with no network try.
        let r = sink.dispatch(&page_alert()).await;
        assert!(r.is_ok(), "rate-limited dispatch must be Ok, got {r:?}");
    }
}
