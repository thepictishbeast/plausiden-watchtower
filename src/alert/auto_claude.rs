//! Auto-Claude fix-loop sink (#317).
//!
//! Spawns a headless `claude -p` invocation against an isolated git
//! worktree of the affected project when a recognised alert fires.
//!
//! # Safety properties
//!
//! - **Default-OFF.** Unless `WATCHTOWER_AUTO_CLAUDE_ENABLE=1` is set,
//!   `from_env` returns `Ok(None)` and the sink does not run. This is
//!   the paywall gate per `feedback_features_behind_paywall`.
//! - **Whitelist-only rule firing.** Only rule names listed in
//!   `WATCHTOWER_AUTO_CLAUDE_RULES` (comma-separated) trigger a Claude
//!   spawn. Unknown rules are logged and dropped. Per the user's
//!   directive on 2026-04-30: "recognized issue classes only — refuse
//!   to wake Claude on unknowns to avoid runaway spend."
//! - **Concurrency cap.** A `tokio::sync::Semaphore` bounds concurrent
//!   Claude processes. If the cap is reached, the alert is logged and
//!   skipped rather than queued. Queueing would defeat the cap (a burst
//!   could backlog hours of work).
//! - **Per-chain project map.** `WATCHTOWER_AUTO_CLAUDE_PROJECT_<CHAIN>`
//!   pins which repo Claude runs against. Alerts whose chain is not
//!   mapped are logged and skipped (we do not guess project paths).
//! - **Isolated worktree.** Each spawn runs `git worktree add` under
//!   `WATCHTOWER_AUTO_CLAUDE_WORKTREE_BASE` so the live working tree is
//!   never modified. The worktree is not auto-cleaned: the operator
//!   reviews / merges / discards each one explicitly.
//! - **Incident transcript.** Stdout + stderr stream to a per-incident
//!   file under `WATCHTOWER_AUTO_CLAUDE_INCIDENT_DIR` so a human can
//!   reconstruct what Claude did even if the daemon restarts.
//!
//! All env-var parsing happens in `from_env`; once constructed the sink
//! is pure data and cannot be reconfigured at runtime.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use thiserror::Error;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::Semaphore;

use crate::alert::{AlertSink, SinkError};
use crate::classify::Alert;

const ENV_ENABLE: &str = "WATCHTOWER_AUTO_CLAUDE_ENABLE";
const ENV_RULES: &str = "WATCHTOWER_AUTO_CLAUDE_RULES";
const ENV_BIN: &str = "WATCHTOWER_AUTO_CLAUDE_BIN";
const ENV_INCIDENT_DIR: &str = "WATCHTOWER_AUTO_CLAUDE_INCIDENT_DIR";
const ENV_WORKTREE_BASE: &str = "WATCHTOWER_AUTO_CLAUDE_WORKTREE_BASE";
const ENV_MAX_CONCURRENT: &str = "WATCHTOWER_AUTO_CLAUDE_MAX_CONCURRENT";
const ENV_PROJECT_PREFIX: &str = "WATCHTOWER_AUTO_CLAUDE_PROJECT_";

const DEFAULT_BIN: &str = "claude";
const DEFAULT_INCIDENT_DIR: &str = "/var/lib/plausiden-watchtower/incidents";
const DEFAULT_WORKTREE_BASE: &str = "/var/lib/plausiden-watchtower/worktrees";
const DEFAULT_MAX_CONCURRENT: usize = 1;

#[derive(Debug, Error)]
pub enum AutoClaudeConfigError {
    #[error("WATCHTOWER_AUTO_CLAUDE_RULES is empty — refusing to enable a sink that would never fire")]
    EmptyRules,
    #[error("WATCHTOWER_AUTO_CLAUDE_MAX_CONCURRENT must be >= 1 (got {0})")]
    BadConcurrency(usize),
    #[error("no WATCHTOWER_AUTO_CLAUDE_PROJECT_* env vars set — refusing to enable a sink with no project map")]
    NoProjects,
    #[error("invalid project env var name {0}: chain segment is empty")]
    EmptyChainKey(String),
}

/// Sink that spawns a headless Claude process per matching alert.
///
/// Construct with [`AutoClaudeSink::from_env`]; do not build by hand
/// outside tests.
pub struct AutoClaudeSink {
    /// Whitelist of rule names that may trigger a spawn. Lookup is by
    /// exact match against `Alert::rule`.
    allowed_rules: Vec<String>,
    /// Map of chain name (the `chain` field of the structured event,
    /// e.g. `"register"`, `"zktls"`, `"mdl"`) to the repo path Claude
    /// should run against.
    projects: HashMap<String, PathBuf>,
    /// Path to the `claude` binary.
    bin: PathBuf,
    /// Directory under which per-incident transcript files are written.
    incident_dir: PathBuf,
    /// Directory under which per-incident git worktrees are created.
    worktree_base: PathBuf,
    /// Bounds in-flight Claude processes.
    permits: Arc<Semaphore>,
}

impl AutoClaudeSink {
    /// Build the sink from environment variables. Returns `Ok(None)` if
    /// the gate variable is unset (default-OFF state). Returns `Err` if
    /// the gate is on but the configuration is incoherent.
    pub fn from_env() -> Result<Option<Self>, AutoClaudeConfigError> {
        let enabled = std::env::var(ENV_ENABLE).ok()
            .map(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);
        if !enabled {
            return Ok(None);
        }

        let allowed_rules: Vec<String> = std::env::var(ENV_RULES)
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if allowed_rules.is_empty() {
            return Err(AutoClaudeConfigError::EmptyRules);
        }

        let bin = std::env::var(ENV_BIN)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_BIN));
        let incident_dir = std::env::var(ENV_INCIDENT_DIR)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_INCIDENT_DIR));
        let worktree_base = std::env::var(ENV_WORKTREE_BASE)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_WORKTREE_BASE));

        let max_concurrent = std::env::var(ENV_MAX_CONCURRENT)
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_MAX_CONCURRENT);
        if max_concurrent == 0 {
            return Err(AutoClaudeConfigError::BadConcurrency(max_concurrent));
        }

        let mut projects: HashMap<String, PathBuf> = HashMap::new();
        for (k, v) in std::env::vars() {
            if let Some(suffix) = k.strip_prefix(ENV_PROJECT_PREFIX) {
                if suffix.is_empty() {
                    return Err(AutoClaudeConfigError::EmptyChainKey(k));
                }
                projects.insert(suffix.to_lowercase(), PathBuf::from(v));
            }
        }
        if projects.is_empty() {
            return Err(AutoClaudeConfigError::NoProjects);
        }

        Ok(Some(Self {
            allowed_rules,
            projects,
            bin,
            incident_dir,
            worktree_base,
            permits: Arc::new(Semaphore::new(max_concurrent)),
        }))
    }

    /// Test-only direct constructor. Does not consult env vars.
    #[cfg(test)]
    fn new(
        allowed_rules: Vec<String>,
        projects: HashMap<String, PathBuf>,
        bin: PathBuf,
        incident_dir: PathBuf,
        worktree_base: PathBuf,
        max_concurrent: usize,
    ) -> Self {
        Self {
            allowed_rules,
            projects,
            bin,
            incident_dir,
            worktree_base,
            permits: Arc::new(Semaphore::new(max_concurrent.max(1))),
        }
    }

    /// Sink-internal preflight: would this alert spawn a Claude run?
    ///
    /// Returns the resolved project path if so, else `None` with the
    /// reason as a string for tracing. Pure function — no side effects.
    fn preflight<'a>(&'a self, alert: &Alert) -> Result<&'a Path, &'static str> {
        if !self.allowed_rules.iter().any(|r| r == &alert.rule) {
            return Err("rule not in WATCHTOWER_AUTO_CLAUDE_RULES whitelist");
        }
        let chain = alert
            .sample_event
            .as_ref()
            .and_then(|e| e.chain.as_deref())
            .ok_or("alert has no chain — cannot resolve project")?;
        let project = self
            .projects
            .get(&chain.to_lowercase())
            .ok_or("chain not in WATCHTOWER_AUTO_CLAUDE_PROJECT_* map")?;
        Ok(project.as_path())
    }

    /// Build the Claude prompt from the alert. Includes the rule, key,
    /// count, window, and a sample log line so Claude has enough context
    /// to begin diagnosing without further prompting.
    fn build_prompt(alert: &Alert) -> String {
        let sample_chain = alert
            .sample_event
            .as_ref()
            .and_then(|e| e.chain.as_deref())
            .unwrap_or("unknown");
        let sample_step = alert
            .sample_event
            .as_ref()
            .and_then(|e| e.step.as_deref())
            .unwrap_or("unknown");
        let sample_rid = alert
            .sample_event
            .as_ref()
            .and_then(|e| e.rid.as_deref())
            .unwrap_or("unknown");
        let sample_msg = alert
            .sample_event
            .as_ref()
            .map(|e| e.message.as_str())
            .unwrap_or("(no sample message)");

        format!(
            "Watchtower alert fired and you are being asked to triage.\n\n\
             - rule:        {rule}\n\
             - key:         {key}\n\
             - count:       {count} events in {window}s\n\
             - chain:       {chain}\n\
             - step:        {step}\n\
             - sample rid:  {rid}\n\
             - sample log:  {msg}\n\n\
             You are running headless against an isolated git worktree. Do not push, \
             do not commit unless the fix is small + obviously correct + tested. If \
             diagnosis requires more context than the sample line, read the chain's \
             structured logs at /var/log/sacredvote/<chain>.log on this VPS.",
            rule = alert.rule,
            key = alert.key,
            count = alert.count,
            window = alert.window_secs,
            chain = sample_chain,
            step = sample_step,
            rid = sample_rid,
            msg = sample_msg,
        )
    }

    /// Build a unique incident slug suitable for a directory name.
    fn incident_slug(alert: &Alert) -> String {
        let ts = alert.fired_at.format("%Y%m%dT%H%M%SZ");
        let safe_key: String = alert
            .key
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        format!("{ts}-{}-{}", alert.rule, safe_key)
    }

    /// Create the per-incident transcript file and return an open
    /// handle. Failures here are non-fatal: we fall back to dispatch-
    /// without-transcript so a broken disk does not silently swallow
    /// the alert.
    async fn open_incident_log(&self, slug: &str) -> Result<(PathBuf, fs::File), SinkError> {
        fs::create_dir_all(&self.incident_dir)
            .await
            .map_err(|e| SinkError::Failed(format!("incident_dir mkdir: {e}")))?;
        let path = self.incident_dir.join(format!("{slug}.log"));
        let file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .await
            .map_err(|e| SinkError::Failed(format!("open incident log {path:?}: {e}")))?;
        Ok((path, file))
    }

    /// Spawn the Claude process in the background and return immediately.
    ///
    /// We do not block dispatch on Claude's exit: a fix run can take
    /// minutes, and the watchtower event loop must keep ingesting logs.
    /// The spawned task owns the permit; releasing it on completion.
    async fn spawn_claude(
        &self,
        alert: &Alert,
        project: &Path,
    ) -> Result<(), SinkError> {
        let permit = match Arc::clone(&self.permits).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(
                    rule = %alert.rule,
                    "auto-claude concurrency cap reached — alert skipped"
                );
                return Err(SinkError::Failed(
                    "auto-claude concurrency cap reached".into(),
                ));
            }
        };

        let slug = Self::incident_slug(alert);
        let (log_path, mut log_file) = self.open_incident_log(&slug).await?;

        let prompt = Self::build_prompt(alert);
        let header = format!(
            "# auto-claude incident\n\
             # slug: {slug}\n\
             # alert.rule: {rule}\n\
             # alert.key:  {key}\n\
             # project:    {project}\n\
             # started:    {started}\n\
             ---\n",
            rule = alert.rule,
            key = alert.key,
            project = project.display(),
            started = Utc::now().to_rfc3339(),
        );
        log_file
            .write_all(header.as_bytes())
            .await
            .map_err(|e| SinkError::Failed(format!("write header: {e}")))?;

        let bin = self.bin.clone();
        let project = project.to_path_buf();
        let worktree_base = self.worktree_base.clone();
        let log_path_ret = log_path.clone();
        let alert_for_task = alert.clone();

        tokio::spawn(async move {
            let _permit = permit;
            let worktree_path = worktree_base.join(&slug);

            if let Err(e) = fs::create_dir_all(&worktree_base).await {
                tracing::error!(error = %e, "auto-claude: worktree_base mkdir failed");
                return;
            }

            let wt = Command::new("git")
                .arg("-C").arg(&project)
                .arg("worktree").arg("add")
                .arg("--detach")
                .arg(&worktree_path)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .await;
            match wt {
                Ok(out) if out.status.success() => {}
                Ok(out) => {
                    tracing::error!(
                        slug = %slug,
                        stderr = %String::from_utf8_lossy(&out.stderr),
                        "auto-claude: git worktree add failed"
                    );
                    return;
                }
                Err(e) => {
                    tracing::error!(slug = %slug, error = %e, "auto-claude: git spawn failed");
                    return;
                }
            }

            let mut cmd = Command::new(&bin);
            cmd.arg("-p").arg(&prompt)
                .arg("--add-dir").arg(&worktree_path)
                .current_dir(&worktree_path)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            tracing::info!(
                slug = %slug,
                rule = %alert_for_task.rule,
                project = %project.display(),
                worktree = %worktree_path.display(),
                "auto-claude: spawning"
            );
            let child = cmd.spawn();
            let mut child = match child {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(slug = %slug, error = %e, "auto-claude: claude spawn failed");
                    return;
                }
            };

            let stdout = child.stdout.take();
            let stderr = child.stderr.take();
            let log_for_stdout = log_path.clone();
            let log_for_stderr = log_path.clone();

            let stdout_task = tokio::spawn(async move {
                if let Some(stdout) = stdout {
                    stream_to_file(stdout, &log_for_stdout, "stdout").await;
                }
            });
            let stderr_task = tokio::spawn(async move {
                if let Some(stderr) = stderr {
                    stream_to_file(stderr, &log_for_stderr, "stderr").await;
                }
            });

            let exit = child.wait().await;
            let _ = stdout_task.await;
            let _ = stderr_task.await;

            match exit {
                Ok(status) => {
                    tracing::info!(
                        slug = %slug,
                        exit_code = status.code(),
                        log = %log_path.display(),
                        "auto-claude: claude exited"
                    );
                }
                Err(e) => {
                    tracing::error!(slug = %slug, error = %e, "auto-claude: wait failed");
                }
            }
        });

        tracing::info!(log = %log_path_ret.display(), "auto-claude dispatched");
        Ok(())
    }
}

async fn stream_to_file(
    mut reader: impl tokio::io::AsyncRead + Unpin + Send + 'static,
    path: &Path,
    label: &str,
) {
    let file = fs::OpenOptions::new()
        .append(true)
        .open(path)
        .await;
    let mut file = match file {
        Ok(f) => f,
        Err(e) => {
            tracing::error!(error = %e, label = %label, "auto-claude: append-open failed");
            return;
        }
    };
    let mut buf = vec![0u8; 8192];
    loop {
        use tokio::io::AsyncReadExt;
        match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                if let Err(e) = file.write_all(&buf[..n]).await {
                    tracing::error!(error = %e, label = %label, "auto-claude: write failed");
                    break;
                }
            }
            Err(e) => {
                tracing::error!(error = %e, label = %label, "auto-claude: read failed");
                break;
            }
        }
    }
}

#[async_trait]
impl AlertSink for AutoClaudeSink {
    fn name(&self) -> &str {
        "auto_claude"
    }

    async fn dispatch(&self, alert: &Alert) -> Result<(), SinkError> {
        let project = match self.preflight(alert) {
            Ok(p) => p.to_path_buf(),
            Err(reason) => {
                tracing::debug!(
                    rule = %alert.rule,
                    key = %alert.key,
                    reason = %reason,
                    "auto-claude: skipping alert"
                );
                return Ok(());
            }
        };
        self.spawn_claude(alert, &project).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::Severity;
    use crate::parse::{Level, StructuredEvent};

    fn alert_with(rule: &str, chain: Option<&str>) -> Alert {
        Alert {
            severity: Severity::Page,
            rule: rule.into(),
            key: "k".into(),
            count: 1,
            window_secs: 60,
            sample_event: chain.map(|c| StructuredEvent {
                level: Level::Error,
                source: "storage".into(),
                chain: Some(c.into()),
                rid: Some("rid-1".into()),
                step: Some("step-1".into()),
                message: "boom".into(),
                raw: "boom".into(),
            }),
            fired_at: Utc::now(),
        }
    }

    fn sink_with_rules_and_chain(rules: &[&str], chain: &str, project: &str) -> AutoClaudeSink {
        let mut projects = HashMap::new();
        projects.insert(chain.to_lowercase(), PathBuf::from(project));
        AutoClaudeSink::new(
            rules.iter().map(|s| (*s).into()).collect(),
            projects,
            PathBuf::from("/usr/local/bin/claude"),
            PathBuf::from("/tmp/wt-incidents"),
            PathBuf::from("/tmp/wt-worktrees"),
            1,
        )
    }

    #[test]
    fn preflight_rejects_unwhitelisted_rule() {
        let s = sink_with_rules_and_chain(&["fatal_any"], "register", "/srv/sacredvote");
        let a = alert_with("error_burst_per_chain", Some("register"));
        let res = s.preflight(&a);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("whitelist"));
    }

    #[test]
    fn preflight_rejects_alert_without_chain() {
        let s = sink_with_rules_and_chain(&["fatal_any"], "register", "/srv/sacredvote");
        let a = alert_with("fatal_any", None);
        let res = s.preflight(&a);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("no chain"));
    }

    #[test]
    fn preflight_rejects_unmapped_chain() {
        let s = sink_with_rules_and_chain(&["fatal_any"], "register", "/srv/sacredvote");
        let a = alert_with("fatal_any", Some("zktls"));
        let res = s.preflight(&a);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("map"));
    }

    #[test]
    fn preflight_accepts_whitelisted_and_mapped() {
        let s = sink_with_rules_and_chain(&["fatal_any"], "register", "/srv/sacredvote");
        let a = alert_with("fatal_any", Some("register"));
        let p = s.preflight(&a).unwrap();
        assert_eq!(p, Path::new("/srv/sacredvote"));
    }

    #[test]
    fn preflight_chain_lookup_is_case_insensitive() {
        let s = sink_with_rules_and_chain(&["fatal_any"], "register", "/srv/sacredvote");
        let a = alert_with("fatal_any", Some("REGISTER"));
        assert!(s.preflight(&a).is_ok());
    }

    #[test]
    fn build_prompt_includes_rule_key_chain() {
        let a = alert_with("fatal_any", Some("zktls"));
        let p = AutoClaudeSink::build_prompt(&a);
        assert!(p.contains("rule:"));
        assert!(p.contains("fatal_any"));
        assert!(p.contains("chain:"));
        assert!(p.contains("zktls"));
        assert!(p.contains("isolated git worktree"));
    }

    #[test]
    fn incident_slug_is_filesystem_safe() {
        let mut a = alert_with("fatal_any", Some("zktls"));
        a.key = "register::login/with spaces".into();
        let slug = AutoClaudeSink::incident_slug(&a);
        assert!(!slug.contains(' '));
        assert!(!slug.contains('/'));
        assert!(!slug.contains(':'));
        assert!(slug.starts_with(&a.fired_at.format("%Y").to_string()));
    }

    #[test]
    fn from_env_default_off() {
        std::env::remove_var(ENV_ENABLE);
        let res = AutoClaudeSink::from_env().unwrap();
        assert!(res.is_none(), "must default OFF when gate is unset");
    }

    #[test]
    fn from_env_enable_without_rules_errors() {
        std::env::set_var(ENV_ENABLE, "1");
        std::env::remove_var(ENV_RULES);
        // Need at least one project to isolate the rules-empty check.
        std::env::set_var("WATCHTOWER_AUTO_CLAUDE_PROJECT_REGISTER", "/srv/x");
        let res = AutoClaudeSink::from_env();
        std::env::remove_var(ENV_ENABLE);
        std::env::remove_var("WATCHTOWER_AUTO_CLAUDE_PROJECT_REGISTER");
        assert!(matches!(res, Err(AutoClaudeConfigError::EmptyRules)));
    }

    #[tokio::test]
    async fn dispatch_unwhitelisted_is_silent_ok() {
        // Skipping (not spawning Claude) should NOT propagate as an
        // error — that would page the operator on every non-fix-class
        // alert. The test verifies dispatch returns Ok(()) when the
        // preflight rejects.
        let s = sink_with_rules_and_chain(&["fatal_any"], "register", "/srv/sacredvote");
        let a = alert_with("error_burst_per_chain", Some("register"));
        s.dispatch(&a).await.unwrap();
    }
}
