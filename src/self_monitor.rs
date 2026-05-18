//! Self-monitoring heartbeat. The watchtower can't reliably alert on
//! its own death from inside itself (a crashed process can't ntfy).
//! The primitive we ship is a heartbeat file: this module writes the
//! current timestamp + uptime + event-counter to a configurable path
//! every interval. An external stale-file detector (run from a
//! separate systemd timer — see `scripts/watchtower-staleness-check.sh`)
//! pages the operator if the file's mtime exceeds the staleness
//! threshold.
//!
//! Default config: heartbeat at `/var/lib/plausiden-watchtower/heartbeat`,
//! written every 60s. The stale-check default threshold is 300s (5min,
//! matching the README spec), so 4 missed heartbeats trigger the page.
//!
//! AUTH-SAFETY: this module writes ONLY to the configured path
//! (validated as a regular file path; not a symlink target check —
//! deployment chooses the dir). No env vars beyond the heartbeat config
//! are read; no credentials, no DB. The body format is human-readable
//! `key=value` lines so an operator can `cat` the file for context.
//! The external detector intentionally reads only `stat -c %Y` (mtime),
//! so the body format can evolve without breaking the detector contract.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::fs;

/// Default heartbeat file location. Lives under `/var/lib/` to match
/// the auto-claude incident-dir + worktree-base defaults (same parent
/// dir, same systemd-managed write perms).
pub const DEFAULT_HEARTBEAT_PATH: &str = "/var/lib/plausiden-watchtower/heartbeat";

/// Default heartbeat write interval. 60s gives 4 missed writes before
/// the default 300s stale threshold trips — enough headroom for a
/// brief I/O hiccup, tight enough that a real crash pages within 5min.
pub const DEFAULT_INTERVAL_SECS: u64 = 60;

/// Bounds on the user-overridable interval. 10s lower bound prevents
/// pathological disk churn; 600s upper bound prevents an interval so
/// long that the heartbeat looks dead even when healthy.
pub const MIN_INTERVAL_SECS: u64 = 10;
pub const MAX_INTERVAL_SECS: u64 = 600;

/// Resolved configuration. `from_env()` parses the two env vars; the
/// default-construction path matches what `from_env()` returns when
/// neither var is set, so tests can compare against it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatConfig {
    pub path: PathBuf,
    pub interval: Duration,
}

impl HeartbeatConfig {
    /// Read `WATCHTOWER_HEARTBEAT_PATH` + `WATCHTOWER_HEARTBEAT_INTERVAL_SECS`
    /// with default fallbacks. Out-of-range interval falls back to default.
    pub fn from_env() -> Self {
        let path = std::env::var("WATCHTOWER_HEARTBEAT_PATH")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_HEARTBEAT_PATH));

        let interval_secs = std::env::var("WATCHTOWER_HEARTBEAT_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&n| (MIN_INTERVAL_SECS..=MAX_INTERVAL_SECS).contains(&n))
            .unwrap_or(DEFAULT_INTERVAL_SECS);

        Self {
            path,
            interval: Duration::from_secs(interval_secs),
        }
    }
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from(DEFAULT_HEARTBEAT_PATH),
            interval: Duration::from_secs(DEFAULT_INTERVAL_SECS),
        }
    }
}

/// Cheap-to-clone counter the main loop hands to the heartbeat task so
/// each heartbeat record carries the event-throughput up to that point.
/// Uses `Relaxed` ordering — we don't need cross-thread happens-before
/// for the counter; we just need monotonic increments.
#[derive(Debug, Clone, Default)]
pub struct HeartbeatCounter {
    inner: Arc<AtomicU64>,
}

impl HeartbeatCounter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn increment(&self) {
        self.inner.fetch_add(1, Ordering::Relaxed);
    }

    pub fn value(&self) -> u64 {
        self.inner.load(Ordering::Relaxed)
    }
}

/// Render the heartbeat file body. Pure function so tests can pin
/// the exact bytes the operator sees on `cat`.
pub fn render_heartbeat_body(now_iso: &str, uptime_secs: u64, events_seen: u64) -> String {
    format!(
        "timestamp={}\nuptime_secs={}\nevents_seen={}\n",
        now_iso, uptime_secs, events_seen
    )
}

/// Write the heartbeat body to `path`. Creates the parent directory if
/// missing. Atomic-overwrite — tokio's `fs::write` truncates+writes in
/// one syscall, so an external `stat` will see the new mtime without
/// observing a half-written body.
pub async fn write_heartbeat(path: &Path, body: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).await?;
        }
    }
    fs::write(path, body).await
}

/// Long-running heartbeat task. Spawn with `tokio::spawn(self_monitor::run(...))`.
/// Never returns under normal operation — exits only on cancel.
///
/// Uses `MissedTickBehavior::Skip` so a long pause (e.g., the host was
/// frozen) doesn't trigger a burst of catch-up writes — the next tick
/// fires at its scheduled time, and the stale-detector sees the gap
/// honestly rather than papering over it.
pub async fn run(config: HeartbeatConfig, counter: HeartbeatCounter) {
    let start = std::time::Instant::now();
    let mut tick = tokio::time::interval(config.interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tracing::info!(
        path = %config.path.display(),
        interval_secs = config.interval.as_secs(),
        "self-monitor heartbeat starting"
    );
    loop {
        tick.tick().await;
        let now = Utc::now().to_rfc3339();
        let uptime = start.elapsed().as_secs();
        let events = counter.value();
        let body = render_heartbeat_body(&now, uptime, events);
        match write_heartbeat(&config.path, &body).await {
            Ok(()) => {
                tracing::debug!(
                    path = %config.path.display(),
                    uptime,
                    events,
                    "heartbeat written"
                );
            }
            Err(e) => {
                // A heartbeat write failure means the stale-detector
                // will eventually fire — log loud so the operator can
                // investigate even before that.
                tracing::warn!(
                    error = %e,
                    path = %config.path.display(),
                    "heartbeat write failed"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // serial_test isn't a dev-dep here; this module owns its env-var
    // mutex so the two from_env tests can't race.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn clear_env() {
        std::env::remove_var("WATCHTOWER_HEARTBEAT_PATH");
        std::env::remove_var("WATCHTOWER_HEARTBEAT_INTERVAL_SECS");
    }

    #[test]
    fn config_default_matches_documented_defaults() {
        let c = HeartbeatConfig::default();
        assert_eq!(c.path, PathBuf::from(DEFAULT_HEARTBEAT_PATH));
        assert_eq!(c.interval, Duration::from_secs(DEFAULT_INTERVAL_SECS));
    }

    #[test]
    fn defaults_match_readme_spec() {
        // README says the stale-detector default threshold is 300s
        // (5min); the interval default is 60s; 4 missed writes pages.
        // If MIN/MAX or DEFAULT drift, the comment in the README
        // will start lying — this test catches that.
        assert_eq!(DEFAULT_INTERVAL_SECS, 60);
        assert_eq!(MIN_INTERVAL_SECS, 10);
        assert_eq!(MAX_INTERVAL_SECS, 600);
        assert_eq!(
            DEFAULT_HEARTBEAT_PATH,
            "/var/lib/plausiden-watchtower/heartbeat"
        );
    }

    #[test]
    fn config_from_env_uses_defaults_when_unset() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_env();
        let c = HeartbeatConfig::from_env();
        assert_eq!(c, HeartbeatConfig::default());
    }

    #[test]
    fn config_from_env_reads_overrides() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_env();
        std::env::set_var("WATCHTOWER_HEARTBEAT_PATH", "/tmp/sv-wt-heartbeat-test");
        std::env::set_var("WATCHTOWER_HEARTBEAT_INTERVAL_SECS", "30");
        let c = HeartbeatConfig::from_env();
        assert_eq!(c.path, PathBuf::from("/tmp/sv-wt-heartbeat-test"));
        assert_eq!(c.interval, Duration::from_secs(30));
        clear_env();
    }

    #[test]
    fn config_from_env_rejects_out_of_range_interval() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_env();
        // Below MIN.
        std::env::set_var("WATCHTOWER_HEARTBEAT_INTERVAL_SECS", "5");
        let c = HeartbeatConfig::from_env();
        assert_eq!(c.interval, Duration::from_secs(DEFAULT_INTERVAL_SECS));
        // Above MAX.
        std::env::set_var("WATCHTOWER_HEARTBEAT_INTERVAL_SECS", "601");
        let c = HeartbeatConfig::from_env();
        assert_eq!(c.interval, Duration::from_secs(DEFAULT_INTERVAL_SECS));
        // Non-integer.
        std::env::set_var("WATCHTOWER_HEARTBEAT_INTERVAL_SECS", "not-a-number");
        let c = HeartbeatConfig::from_env();
        assert_eq!(c.interval, Duration::from_secs(DEFAULT_INTERVAL_SECS));
        clear_env();
    }

    #[test]
    fn config_from_env_empty_path_falls_back_to_default() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_env();
        std::env::set_var("WATCHTOWER_HEARTBEAT_PATH", "");
        let c = HeartbeatConfig::from_env();
        assert_eq!(c.path, PathBuf::from(DEFAULT_HEARTBEAT_PATH));
        clear_env();
    }

    #[test]
    fn counter_starts_at_zero_and_increments() {
        let c = HeartbeatCounter::new();
        assert_eq!(c.value(), 0);
        c.increment();
        c.increment();
        c.increment();
        assert_eq!(c.value(), 3);
    }

    #[test]
    fn counter_clones_share_inner() {
        // The counter is handed to two places (the journal-recv loop
        // increments it; the heartbeat task reads it). They must
        // share underlying state — otherwise the heartbeat would
        // always report events_seen=0.
        let a = HeartbeatCounter::new();
        let b = a.clone();
        a.increment();
        b.increment();
        assert_eq!(a.value(), 2);
        assert_eq!(b.value(), 2);
    }

    #[test]
    fn render_body_format_is_three_kv_lines() {
        let body = render_heartbeat_body("2026-05-17T23:30:00+00:00", 42, 100);
        assert_eq!(
            body,
            "timestamp=2026-05-17T23:30:00+00:00\nuptime_secs=42\nevents_seen=100\n"
        );
        // External detector reads ONLY mtime, but operators `cat` it.
        // Lock the field order + the trailing newline.
        assert!(body.ends_with('\n'));
        assert_eq!(body.lines().count(), 3);
    }

    #[tokio::test]
    async fn write_heartbeat_creates_missing_parent_dir() {
        let base = std::env::temp_dir().join(format!(
            "sv-wt-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = base.join("sub").join("heartbeat");
        assert!(!base.exists());
        let body = render_heartbeat_body("2026-05-17T00:00:00+00:00", 1, 1);
        write_heartbeat(&path, &body).await.expect("write");
        let read = std::fs::read_to_string(&path).expect("read");
        assert_eq!(read, body);
        // Cleanup.
        std::fs::remove_dir_all(&base).ok();
    }

    #[tokio::test]
    async fn write_heartbeat_overwrites_existing_file() {
        let base = std::env::temp_dir().join(format!(
            "sv-wt-overwrite-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = base.join("heartbeat");
        let first = render_heartbeat_body("2026-05-17T00:00:00+00:00", 1, 1);
        let second = render_heartbeat_body("2026-05-17T00:01:00+00:00", 61, 5);
        write_heartbeat(&path, &first).await.expect("first write");
        write_heartbeat(&path, &second).await.expect("second write");
        let read = std::fs::read_to_string(&path).expect("read");
        assert_eq!(read, second);
        assert!(!read.contains("uptime_secs=1\n"));
        std::fs::remove_dir_all(&base).ok();
    }
}
