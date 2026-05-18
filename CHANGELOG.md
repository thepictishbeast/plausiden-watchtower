# Changelog

All notable changes to `plausiden-watchtower` are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/) (with the
caveat that this is engineering-development software per the
[Adversarial Validation Protocol v2](https://github.com/thepictishbeast/PlausiDen-AVP-Doctrine/blob/main/AVP2_PROTOCOL.md) —
no commit has reached `SHIP-DECISION:` status yet).

## [Unreleased]

### Changed
- Repository hygiene pass (LOOP-V3.1#72, #81): `cargo fmt --check` clean
  across all modules + `cargo audit` baseline established (173 deps /
  0 advisories). `cargo clippy --all-targets -- -D warnings` was already
  clean.

## [0.1.0] — 2026-05-17 (self-monitoring complete)

This release marks the four-layer scaffold complete + the load-bearing
self-monitoring story landed.

### Added (LOOP-V3.1#70, issue #318)
- `src/self_monitor.rs` — lib-level heartbeat module. `HeartbeatConfig`
  reads `WATCHTOWER_HEARTBEAT_PATH` (default
  `/var/lib/plausiden-watchtower/heartbeat`) and
  `WATCHTOWER_HEARTBEAT_INTERVAL_SECS` (default 60, clamp `[10, 600]`).
  `HeartbeatCounter` is an `Arc<AtomicU64>` shared with the main
  recv-loop. `run()` writes a human-readable `timestamp / uptime_secs /
  events_seen` file every interval via atomic `tokio::fs::write`.
- `scripts/watchtower-staleness-check.sh` — external stale-detector
  run from a separate systemd timer. Reads ONLY `stat -c %Y` (mtime)
  so the file body format can evolve without breaking the contract.
  Pages ntfy with `Priority: urgent` when age exceeds threshold
  (default 300 s = 5 min = 4 missed heartbeats). The daemon CANNOT
  alert on its own death from inside itself — this is the fallback.
- README `Self-monitoring heartbeat` section: env-var table +
  recommended systemd timer recipe.

### Added (publishing posture)
- `02672cb`: README banner — DO NOT USE — UNVERIFIED — UNSAFE.
  Publishes the AVP-2 default verdict ("STILL BROKEN until proven
  innocent through 36 verification passes") prominently. License
  `FSL-1.1-MIT` (source-available, auto-converts to MIT in 2 years).

### Added (#317, AutoClaudeSink — default-OFF)
- `src/alert/auto_claude.rs` — spawns headless `claude -p` against
  an isolated git worktree when a whitelisted alert fires. Per the
  user directive "refuse to wake Claude on unknowns to avoid runaway
  spend." Safety properties: whitelist-only firing, chain → project
  map required, concurrency cap (semaphore — saturated alerts are
  logged + skipped, not queued), `git worktree add --detach` for
  isolation, per-incident transcript stream-to-file.

### Added (#316, ntfy + email sinks)
- `src/alert/ntfy.rs` — POSTs to a configurable ntfy server +
  topic. Token-bucket rate-limit (default 10/min) so a flapping log
  doesn't pager-storm.
- `src/alert/email.rs` — `mail`-compatible binary invocation. Strict
  ceiling: only `Page` severity triggers email; per-(rule, key) 6 h
  dedup; 4 emails/day daily cap. Email in inbox means "drop
  everything", not "we shipped a thing".

### Added (#315, scaffold)
- `src/parse.rs` — log-line parser for `[time] [LEVEL] [source]
  chain=… rid=… step=n/m description` structured emission.
- `src/classify.rs` — sliding-window threshold engine with these
  default rules:
  - FATAL anywhere → 1 in any window → page
  - ERROR in any chain → 5 in 60 s → page
  - ERROR in any chain → 1 in 600 s → warn
  - chain step REJECT clusters → 10 same-step in 60 s → warn
  - WARN baseline → 50 in 600 s → info
- `src/alert/mod.rs` — `AlertSink` trait + `LoggerSink` (always-on,
  so alerts never silently drop) + `MultiSink` with per-sink failure
  isolation.
- `src/journal.rs` — live `journalctl --follow` tailer (only with
  the `journal` feature so the parser/classifier libs build on any
  machine without `libsystemd`).

[Unreleased]: https://github.com/thepictishbeast/plausiden-watchtower/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/thepictishbeast/plausiden-watchtower/releases/tag/v0.1.0
