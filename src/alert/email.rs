//! Email sink. Severity-gated to `Page` only and capped tightly per
//! `feedback_email_important_items.md` ("Default: do NOT send email").
//!
//! Default policy:
//! - Only `Severity::Page` alerts trigger email.
//! - Per-(rule,key) dedup: one email per 6 hours.
//! - Hard daily cap: 4 emails per 24h, regardless of dedup state.
//! - Subject prefix `[SV Action] watchtower:` so user filters work.
//!
//! Why shell out to `mail` rather than SMTP directly?
//! - The VPS already runs postfix and the canary scripts use `mail`
//!   identically (`/etc/sacred-vote/ntfy.env` pattern, etc.). One less
//!   moving part, one fewer credential file, no new auth boundary.
//! - `mail` handles UTF-8 via the `-a` header per
//!   `feedback_email_utf8_headers.md`.
//!
//! Test strategy: the test injects a fake `mail` binary path that
//! records argv to a temp file, lets us assert subject + recipient
//! without sending real mail. Same pattern as the journalctl tailer.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::alert::rate_limit::{DedupCache, TokenBucket};
use crate::alert::{AlertSink, SinkError};
use crate::classify::{Alert, Severity};

const DEFAULT_FROM: &str = "alerts@sacredvote.org";
const DEFAULT_BIN: &str = "mail";
const SUBJECT_PREFIX: &str = "[SV Action] watchtower:";
const DEDUP_HOURS: u64 = 6;
const DAILY_CAP: u32 = 4;

pub struct EmailSink {
    to: String,
    from: String,
    bin: PathBuf,
    daily_bucket: Mutex<TokenBucket>,
    dedup: Mutex<DedupCache>,
}

#[derive(Debug, thiserror::Error)]
pub enum EmailConfigError {
    #[error("WATCHTOWER_EMAIL_TO empty or unset")]
    NoRecipient,
}

impl EmailSink {
    pub fn new(to: impl Into<String>, from: impl Into<String>, bin: impl Into<PathBuf>) -> Self {
        Self {
            to: to.into(),
            from: from.into(),
            bin: bin.into(),
            daily_bucket: Mutex::new(TokenBucket::new(DAILY_CAP, Duration::from_secs(24 * 3600))),
            dedup: Mutex::new(DedupCache::new(Duration::from_secs(DEDUP_HOURS * 3600))),
        }
    }

    /// Build from environment. Returns `Ok(None)` if `WATCHTOWER_EMAIL_TO`
    /// is absent — that's the explicit way to disable the sink.
    pub fn from_env() -> Result<Option<Self>, EmailConfigError> {
        Self::from_env_with(|k| std::env::var(k).ok())
    }

    /// Same as [`from_env`] but with an injectable env-lookup closure
    /// so tests can stay pure under `forbid(unsafe_code)`.
    pub fn from_env_with(
        getenv: impl Fn(&str) -> Option<String>,
    ) -> Result<Option<Self>, EmailConfigError> {
        let Some(to) = getenv("WATCHTOWER_EMAIL_TO") else {
            return Ok(None);
        };
        if to.trim().is_empty() {
            return Ok(None);
        }
        let from = getenv("WATCHTOWER_EMAIL_FROM").unwrap_or_else(|| DEFAULT_FROM.into());
        let bin = getenv("WATCHTOWER_EMAIL_BIN").unwrap_or_else(|| DEFAULT_BIN.into());
        Ok(Some(Self::new(to, from, bin)))
    }

    fn dedup_key(&self, alert: &Alert) -> String {
        format!("{}::{}", alert.rule, alert.key)
    }

    fn subject(&self, alert: &Alert) -> String {
        let chain = alert
            .sample_event
            .as_ref()
            .and_then(|e| e.chain.as_deref())
            .unwrap_or("unknown");
        format!(
            "{} {} on {} (count={})",
            SUBJECT_PREFIX, alert.rule, chain, alert.count
        )
    }

    fn body(&self, alert: &Alert) -> String {
        let mut out = String::new();
        out.push_str(&format!("Severity: {:?}\n", alert.severity));
        out.push_str(&format!("Rule:     {}\n", alert.rule));
        out.push_str(&format!("Key:      {}\n", alert.key));
        out.push_str(&format!("Count:    {}\n", alert.count));
        out.push_str(&format!("Window:   {} seconds\n", alert.window_secs));
        out.push_str(&format!("Fired:    {}\n", alert.fired_at.to_rfc3339()));
        if let Some(s) = &alert.sample_event {
            out.push_str("\nSample event:\n");
            if let Some(c) = &s.chain {
                out.push_str(&format!("  chain={c}\n"));
            }
            if let Some(r) = &s.rid {
                out.push_str(&format!("  rid={r}\n"));
            }
            if let Some(st) = &s.step {
                out.push_str(&format!("  step={st}\n"));
            }
            out.push_str(&format!("  source={}\n", s.source));
            out.push_str(&format!("  message={}\n", s.message));
        }
        out.push_str(
            "\n--\nFrom plausiden-watchtower. Reply to this email to ack — the daemon \
             keeps a 6h dedup so you won't be re-paged for the same rule/key.\n",
        );
        out
    }
}

#[async_trait]
impl AlertSink for EmailSink {
    fn name(&self) -> &str {
        "email"
    }

    async fn dispatch(&self, alert: &Alert) -> Result<(), SinkError> {
        // Severity gate — non-Page alerts never trigger email.
        if alert.severity != Severity::Page {
            return Ok(());
        }

        // Per-(rule,key) dedup.
        if !self
            .dedup
            .lock()
            .map_err(|e| SinkError::Failed(format!("dedup poisoned: {e}")))?
            .should_emit(&self.dedup_key(alert))
        {
            tracing::info!(
                rule = %alert.rule,
                key = %alert.key,
                "email suppressed by 6h per-key dedup"
            );
            return Ok(());
        }

        // Daily cap.
        if !self
            .daily_bucket
            .lock()
            .map_err(|e| SinkError::Failed(format!("daily bucket poisoned: {e}")))?
            .try_take()
        {
            tracing::warn!(
                rule = %alert.rule,
                key = %alert.key,
                "email suppressed by daily cap of {DAILY_CAP}"
            );
            return Ok(());
        }

        let subject = self.subject(alert);
        let body = self.body(alert);

        let mut child = Command::new(&self.bin)
            .arg("-s")
            .arg(&subject)
            .arg("-a")
            .arg("Content-Type: text/plain; charset=UTF-8")
            .arg("-r")
            .arg(&self.from)
            .arg(&self.to)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| SinkError::Failed(format!("spawn {}: {e}", self.bin.display())))?;

        if let Some(stdin) = child.stdin.as_mut() {
            stdin
                .write_all(body.as_bytes())
                .await
                .map_err(|e| SinkError::Failed(format!("write body: {e}")))?;
        }
        // Closing stdin signals EOF to mail(1).
        drop(child.stdin.take());

        let status = child
            .wait()
            .await
            .map_err(|e| SinkError::Failed(format!("wait: {e}")))?;
        if !status.success() {
            return Err(SinkError::Failed(format!(
                "mail exited {} for {}",
                status.code().unwrap_or(-1),
                self.to
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

    fn warn_alert() -> Alert {
        Alert {
            severity: Severity::Warn,
            rule: "warn_baseline_global".into(),
            key: "global".into(),
            count: 50,
            window_secs: 600,
            sample_event: None,
            fired_at: Utc::now(),
        }
    }

    /// Same noexec-aware temp dir picker as journal.rs uses.
    fn exec_tmp() -> std::path::PathBuf {
        let base = std::env::var("CARGO_MANIFEST_DIR")
            .map(|d| std::path::PathBuf::from(d).join("target").join("test-tmp"))
            .unwrap_or_else(|_| std::env::temp_dir());
        let dir = base.join(format!(
            "watchtower-email-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Writes a stub `mail` binary that captures argv + stdin to two
    /// files in `dir`, then exits 0.
    fn write_capture_mail(dir: &std::path::Path) -> std::path::PathBuf {
        let argv_log = dir.join("argv.txt");
        let stdin_log = dir.join("stdin.txt");
        let bin = dir.join("fake-mail.sh");
        let script = format!(
            "#!/usr/bin/env sh\nprintf '%s\\n' \"$@\" > {argv}\ncat > {stdin}\nexit 0\n",
            argv = argv_log.display(),
            stdin = stdin_log.display()
        );
        std::fs::write(&bin, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut p = std::fs::metadata(&bin).unwrap().permissions();
            p.set_mode(0o755);
            std::fs::set_permissions(&bin, p).unwrap();
        }
        bin
    }

    #[tokio::test]
    async fn skips_non_page_severity() {
        let dir = exec_tmp();
        let bin = write_capture_mail(&dir);
        let sink = EmailSink::new("william@plausiden.com", DEFAULT_FROM, bin);
        sink.dispatch(&warn_alert()).await.unwrap();
        // No mail should have been invoked.
        assert!(!dir.join("argv.txt").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn page_invokes_mail_with_subject_and_recipient() {
        let dir = exec_tmp();
        let bin = write_capture_mail(&dir);
        let sink = EmailSink::new("william@plausiden.com", DEFAULT_FROM, bin);
        sink.dispatch(&page_alert()).await.unwrap();
        let argv = std::fs::read_to_string(dir.join("argv.txt")).unwrap();
        let stdin = std::fs::read_to_string(dir.join("stdin.txt")).unwrap();
        assert!(
            argv.contains(SUBJECT_PREFIX),
            "subject prefix not in argv: {argv}"
        );
        assert!(
            argv.contains("william@plausiden.com"),
            "recipient missing: {argv}"
        );
        assert!(
            argv.contains("Content-Type: text/plain; charset=UTF-8"),
            "UTF-8 header missing: {argv}"
        );
        assert!(stdin.contains("Severity: Page"));
        assert!(stdin.contains("Rule:     fatal_any"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn dedup_suppresses_repeat_within_window() {
        let dir = exec_tmp();
        let bin = write_capture_mail(&dir);
        let sink = EmailSink::new("william@plausiden.com", DEFAULT_FROM, bin);
        sink.dispatch(&page_alert()).await.unwrap();
        // Capture argv from first invocation.
        let argv_path = dir.join("argv.txt");
        let first_modified = std::fs::metadata(&argv_path).unwrap().modified().unwrap();
        // Wait a hair so mtime would advance if a second invocation occurred.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        sink.dispatch(&page_alert()).await.unwrap();
        let second_modified = std::fs::metadata(&argv_path).unwrap().modified().unwrap();
        assert_eq!(
            first_modified, second_modified,
            "second dispatch should NOT have invoked mail"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn from_env_returns_none_without_recipient() {
        let getenv = |_: &str| None;
        assert!(matches!(EmailSink::from_env_with(getenv), Ok(None)));
    }

    #[test]
    fn from_env_returns_none_with_blank_recipient() {
        let getenv = |k: &str| match k {
            "WATCHTOWER_EMAIL_TO" => Some("   ".to_string()),
            _ => None,
        };
        assert!(matches!(EmailSink::from_env_with(getenv), Ok(None)));
    }

    #[test]
    fn from_env_uses_defaults_when_optionals_unset() {
        let getenv = |k: &str| match k {
            "WATCHTOWER_EMAIL_TO" => Some("william@plausiden.com".to_string()),
            _ => None,
        };
        let sink = EmailSink::from_env_with(getenv).unwrap().unwrap();
        assert_eq!(sink.from, DEFAULT_FROM);
        assert_eq!(sink.bin, std::path::PathBuf::from(DEFAULT_BIN));
    }

    #[test]
    fn subject_includes_rule_and_chain() {
        let sink = EmailSink::new("a@b", DEFAULT_FROM, "mail");
        let mut a = page_alert();
        a.sample_event = Some(crate::parse::StructuredEvent {
            level: crate::parse::Level::Fatal,
            source: "storage".into(),
            chain: Some("REGCHAIN".into()),
            rid: Some("rid".into()),
            step: None,
            message: "boom".into(),
            raw: "[12:00:00] [FATAL] [storage] chain=REGCHAIN rid=rid boom".into(),
        });
        let s = sink.subject(&a);
        assert!(s.contains("watchtower:"));
        assert!(s.contains("fatal_any"));
        assert!(s.contains("REGCHAIN"));
    }
}
