//! Live journalctl reader. Spawns `journalctl -f --output=json -u <unit>`
//! per configured systemd unit and pumps each line into the watcher
//! channel.
//!
//! We deliberately use the CLI rather than the libsystemd FFI here:
//! - Zero unsafe deps in the hot path.
//! - Easy to test on a dev box (set `JOURNALCTL_BIN` to a fixture
//!   shell script that emits canned JSON lines).
//! - Survives journalctl format changes within a major version.
//!
//! Each line out of `journalctl --output=json` is a JSON object whose
//! `MESSAGE` field is the application's log line. We forward the
//! message verbatim to [`crate::parse::parse_line`].

use std::process::Stdio;

use serde::Deserialize;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

#[derive(Debug, Error)]
pub enum JournalError {
    #[error("failed to spawn journalctl: {0}")]
    Spawn(String),

    #[error("journalctl exited unexpectedly")]
    Exited,
}

#[derive(Debug, Deserialize)]
struct JournalLine {
    #[serde(rename = "MESSAGE")]
    message: Option<String>,
    #[serde(rename = "_SYSTEMD_UNIT")]
    unit: Option<String>,
}

/// Spawn a journalctl tailer for the given units. Each tailed line is
/// forwarded as `(unit, raw_message)` on the returned receiver.
///
/// Cancels cleanly when the receiver is dropped (the spawned task
/// observes the closed channel and aborts the child process).
pub fn spawn(
    units: Vec<String>,
    journalctl_bin: Option<String>,
) -> Result<mpsc::Receiver<(String, String)>, JournalError> {
    let bin = journalctl_bin
        .or_else(|| std::env::var("JOURNALCTL_BIN").ok())
        .unwrap_or_else(|| "journalctl".to_string());

    let mut args: Vec<String> = vec!["-f".into(), "--output=json".into()];
    for u in &units {
        args.push("-u".into());
        args.push(u.clone());
    }

    let mut child = Command::new(&bin)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| JournalError::Spawn(e.to_string()))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| JournalError::Spawn("no stdout".into()))?;

    let (tx, rx) = mpsc::channel::<(String, String)>(1024);

    tokio::spawn(async move {
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    let Some(parsed) = serde_json::from_str::<JournalLine>(&line).ok() else {
                        continue;
                    };
                    let (Some(msg), Some(unit)) = (parsed.message, parsed.unit) else {
                        continue;
                    };
                    if tx.send((unit, msg)).await.is_err() {
                        // Receiver gone, time to bail.
                        let _ = child.kill().await;
                        return;
                    }
                }
                Ok(None) => {
                    tracing::warn!("journalctl stdout closed");
                    return;
                }
                Err(e) => {
                    tracing::error!(error = %e, "error reading journalctl stdout");
                    return;
                }
            }
        }
    });

    Ok(rx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_journal_line_struct() {
        let raw =
            r#"{"MESSAGE":"hello world","_SYSTEMD_UNIT":"sacredvote.service","other":"ignored"}"#;
        let parsed: JournalLine = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.message.as_deref(), Some("hello world"));
        assert_eq!(parsed.unit.as_deref(), Some("sacredvote.service"));
    }

    #[test]
    fn missing_message_skips_silently() {
        // No MESSAGE field means the line carries no log payload — we
        // skip it rather than synthesize one. Mirrors production
        // journal lines for unit-state-change events.
        let raw = r#"{"_SYSTEMD_UNIT":"sacredvote.service"}"#;
        let parsed: JournalLine = serde_json::from_str(raw).unwrap();
        assert!(parsed.message.is_none());
        assert!(parsed.unit.is_some());
    }

    #[test]
    fn missing_unit_skips_silently() {
        let raw = r#"{"MESSAGE":"some message"}"#;
        let parsed: JournalLine = serde_json::from_str(raw).unwrap();
        assert!(parsed.message.is_some());
        assert!(parsed.unit.is_none());
    }

    #[tokio::test]
    async fn live_tailer_smoke_test() {
        // Substitute a tiny shell script that emits two JSON lines and
        // exits. We verify that we receive both, then channel close.
        //
        // Hardened-host note: many production VPSes mount /tmp with
        // `noexec`, so std::env::temp_dir() can't host an executable
        // script. We anchor the temp dir under the crate's own target/
        // directory (always exec-capable, since it already hosts the
        // test binary itself) and fall back to temp_dir() only when
        // CARGO_MANIFEST_DIR is unavailable (non-cargo runner).
        let base = std::env::var("CARGO_MANIFEST_DIR")
            .map(|d| std::path::PathBuf::from(d).join("target").join("test-tmp"))
            .unwrap_or_else(|_| std::env::temp_dir());
        let tmp = base.join(format!("watchtower-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let fake = tmp.join("fake-journalctl.sh");
        std::fs::write(
            &fake,
            "#!/usr/bin/env sh\n\
             echo '{\"MESSAGE\":\"a\",\"_SYSTEMD_UNIT\":\"u.service\"}'\n\
             echo '{\"MESSAGE\":\"b\",\"_SYSTEMD_UNIT\":\"u.service\"}'\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut p = std::fs::metadata(&fake).unwrap().permissions();
            p.set_mode(0o755);
            std::fs::set_permissions(&fake, p).unwrap();
        }

        let mut rx = spawn(
            vec!["u.service".into()],
            Some(fake.to_string_lossy().into()),
        )
        .unwrap();
        let first = rx.recv().await.expect("first line");
        let second = rx.recv().await.expect("second line");
        assert_eq!(first.0, "u.service");
        assert_eq!(first.1, "a");
        assert_eq!(second.1, "b");

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
