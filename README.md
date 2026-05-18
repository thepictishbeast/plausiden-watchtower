> # ⚠️ DO NOT USE — UNVERIFIED — UNSAFE ⚠️
>
> This software is **unverified and unsafe for any production use**.
> It is published publicly only for transparency, third-party audit,
> and reproducibility. Treat every commit as guilty until proven
> innocent.
>
> By using this code you accept:
> - **No warranty** of any kind, express or implied.
> - **No fitness** for any particular purpose.
> - **No guarantee** of correctness, safety, or freedom from defects.
> - **Zero liability** on the maintainer for any damages — data loss,
>   security compromise, financial loss, or any consequential damages.
>
> The code is under active engineering development per the
> [Adversarial Validation Protocol v2](https://github.com/thepictishbeast/PlausiDen-AVP-Doctrine/blob/main/AVP2_PROTOCOL.md).
> Every commit's default verdict is **STILL BROKEN**. AVP-2 requires
> a minimum of 36 verification passes before a `SHIP-DECISION:`
> annotation may be considered. **No commit in this repository has
> reached `SHIP-DECISION:` status.**

# plausiden-watchtower

Tails per-chain structured logs from the PlausiDen / Sacred Vote service
stack, classifies issues by severity and chain, and dispatches alerts to
configured sinks (ntfy + email).

## Why

The full-chain audit initiative (2026-04-30) has every request emit
structured `chain=<name> rid=<id> step=<n/m> <event>` lines through the
sacredvote logger. That produces enormous log volume that no human can
tail. Without a watchtower, structured logs are a forensic tool only —
with one, they become a live early-warning system.

## Status

| Layer                    | Status   | Issue |
|--------------------------|----------|-------|
| Log line parser          | Shipped  | #315  |
| Severity classifier      | Shipped  | #315  |
| Threshold rules engine   | Shipped  | #315  |
| Journal reader (live)    | Shipped  | #315  |
| ntfy alert sink          | Shipped  | #316  |
| Email alert sink         | Shipped  | #316  |
| Token-bucket rate-limit  | Shipped  | #316  |
| Auto-Claude fix loop     | Shipped  | #317  |
| Self-monitoring pings    | Shipped  | #318  |

## Log-line format

The watchtower expects the format emitted by `server/logger.ts`:

```
[3:55:50 PM] [WARN] [security] chain=registration rid=abc123 step=POST /api/register 5/8 REJECT duplicate piiHash
```

Parsed as:

- `level` — INFO / WARN / ERROR / FATAL / DEBUG
- `source` — bracketed source tag (e.g., `security`, `identity`, `csp`)
- `chain` — present when the line is part of a chain (registration / zktls / mdl / auth)
- `rid` — request ID (unique per HTTP request, ties chain steps together)
- `step` — `<index>/<total> <description>` showing where in the chain the line was emitted
- `message` — full remainder for context

## Classification rules

(See `src/classify.rs` for the full ruleset.)

| Class                         | Threshold            | Severity |
|-------------------------------|----------------------|----------|
| FATAL anywhere                | 1 in any window      | page     |
| ERROR in any chain            | 5 in 60s             | page     |
| ERROR in any chain            | 1 in 600s            | warn     |
| chain step REJECT clusters    | 10 same-step in 60s  | warn     |
| WARN baseline                 | 50 in 600s           | info     |

## Running the daemon

(Requires `journal` feature.)

```sh
cargo run --features journal --release
```

`LoggerSink` is always-on so the daemon never silently drops alerts.
ntfy and email turn on when their env vars are set.

### Configuration (env vars)

| Var                            | Required | Default                        | Effect                                                                |
|--------------------------------|----------|--------------------------------|-----------------------------------------------------------------------|
| `WATCHTOWER_UNITS`             | no       | every Sacred Vote service      | comma-separated systemd units to tail                                 |
| `JOURNALCTL_BIN`               | no       | `journalctl`                   | path override (used in tests)                                         |
| `NTFY_URL`                     | yes¹     | —                              | full URL of the ntfy server (e.g. `http://127.0.0.1:8090`)            |
| `WATCHTOWER_NTFY_TOPIC`        | no       | `sacredvote-watchtower`        | topic to POST to                                                      |
| `NTFY_TOKEN`                   | no       | —                              | bearer token, required against the production ntfy server             |
| `WATCHTOWER_NTFY_RATE_PER_MIN` | no       | `10`                           | token-bucket capacity per minute                                      |
| `WATCHTOWER_EMAIL_TO`          | yes²     | —                              | recipient (`Page` severity only)                                      |
| `WATCHTOWER_EMAIL_FROM`        | no       | `alerts@sacredvote.org`        | envelope sender (NEVER `tim@sacred.vote`)                             |
| `WATCHTOWER_EMAIL_BIN`         | no       | `mail`                         | path to `mail`-compatible binary                                      |

¹ Required only to *enable* the ntfy sink. Absent → ntfy disabled, daemon still runs.
² Required only to *enable* the email sink. Absent → email disabled, daemon still runs.

### Auto-Claude sink (#317) — default-OFF

Spawns a headless `claude -p` process against an isolated git worktree
when a whitelisted alert fires. Default-OFF per
`feedback_features_behind_paywall`; enable with:

| Var                                           | Required | Default                                   | Notes |
|---|---|---|---|
| `WATCHTOWER_AUTO_CLAUDE_ENABLE`               | yes      | unset                                     | gate; set to `1`/`true`/`yes`/`on` to enable |
| `WATCHTOWER_AUTO_CLAUDE_RULES`                | yes      | —                                         | comma-separated rule whitelist (e.g. `fatal_any,error_burst_per_chain`); only these spawn Claude |
| `WATCHTOWER_AUTO_CLAUDE_PROJECT_<CHAIN>`      | yes ≥1   | —                                         | per-chain repo path (e.g. `WATCHTOWER_AUTO_CLAUDE_PROJECT_REGISTER=/srv/sacredvote`) |
| `WATCHTOWER_AUTO_CLAUDE_BIN`                  | no       | `claude`                                  | path to the Claude CLI |
| `WATCHTOWER_AUTO_CLAUDE_INCIDENT_DIR`         | no       | `/var/lib/plausiden-watchtower/incidents` | per-incident transcript files |
| `WATCHTOWER_AUTO_CLAUDE_WORKTREE_BASE`        | no       | `/var/lib/plausiden-watchtower/worktrees` | per-incident `git worktree add` target |
| `WATCHTOWER_AUTO_CLAUDE_MAX_CONCURRENT`       | no       | `1`                                       | hard cap on in-flight Claude processes |

**Safety properties:**

- **Whitelist-only firing.** Rules outside `WATCHTOWER_AUTO_CLAUDE_RULES`
  are logged at `debug` and dropped. Per the user's directive: "refuse to
  wake Claude on unknowns to avoid runaway spend."
- **Chain → project map required.** Alerts whose `chain` is not in any
  `WATCHTOWER_AUTO_CLAUDE_PROJECT_*` env var are dropped (no path
  guessing).
- **Concurrency cap.** When the semaphore is saturated the alert is
  logged + skipped, **not queued**. Queueing would let a burst backlog
  hours of Claude time.
- **Isolated worktree.** Each spawn runs `git worktree add --detach` so
  the live working tree is never touched. Worktrees are not auto-cleaned;
  the operator reviews/merges/discards each one explicitly.
- **Per-incident transcript.** stdout + stderr stream to a unique file
  in `incident_dir` so the operator can reconstruct what Claude did
  even if the daemon restarts mid-run.

### Self-monitoring heartbeat (#318)

The daemon writes a heartbeat file every interval; an external
`scripts/watchtower-staleness-check.sh` (run from a separate systemd
timer or cron) pages via ntfy if the file's mtime exceeds the
staleness threshold. The daemon CANNOT alert on its own death — this
is the load-bearing fallback.

| Var                                    | Required | Default                                       | Effect                                                          |
|---|---|---|---|
| `WATCHTOWER_HEARTBEAT_PATH`            | no       | `/var/lib/plausiden-watchtower/heartbeat`     | file path written by the daemon                                 |
| `WATCHTOWER_HEARTBEAT_INTERVAL_SECS`   | no       | `60` (clamp `[10, 600]`)                      | how often the daemon writes; out-of-range falls back to default |
| `WATCHTOWER_HEARTBEAT_STALE_SECS`      | no       | `300`                                         | external script's threshold (alert when mtime older than this)  |

The file body is human-readable `key=value` lines (`timestamp`, `uptime_secs`,
`events_seen`) so `cat /var/lib/plausiden-watchtower/heartbeat` is a
useful liveness probe on its own. The external detector reads ONLY
the file's mtime via `stat -c %Y`, so the body format can evolve
without breaking the contract.

Recommended systemd timer for the detector:

```ini
# /etc/systemd/system/watchtower-staleness-check.timer
[Unit]
Description=plausiden-watchtower staleness check

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min

[Install]
WantedBy=timers.target
```

### Email policy

Strict ceiling per `feedback_email_important_items.md`:

- **Severity gate:** only `Page` alerts trigger email. `Warn` and `Info`
  never do, regardless of count.
- **Per-(rule,key) dedup:** once an email goes out for a given (rule,
  key), the next 6h are suppressed. The repeat is logged at info-level
  in the daemon's tracing output but does not page.
- **Daily cap:** at most 4 emails in any rolling 24h, regardless of
  dedup state. Fifth `Page` is logged + dropped.

The intent is that an email landing in the inbox means "drop everything"
— not "we shipped a thing".

## Building without the journal feature

The parser and classifier libs build on any machine without `libsystemd`:

```sh
cargo build --lib
cargo test --lib
```

This is the path used in CI and on dev laptops.

## Production deployment

Two paths: `deploy/install.sh` (cargo + systemd; works anywhere) or
`flake.nix` (NixOS module; reproducible, declarative).

### Path 1 — `deploy/install.sh` (cargo + systemd)

Drop-in installer at `deploy/install.sh`. Idempotent: re-running just
refreshes the binary + restarts. Safe after `git pull`.

```sh
sudo ./deploy/install.sh
```

Installs:
- `/opt/plausiden-watchtower/bin/plausiden-watchtower` — release binary
  built with `--features journal`
- `/etc/systemd/system/plausiden-watchtower.service` — hardened unit
  (see `deploy/systemd/plausiden-watchtower.service` for the full
  systemd directive list; mirrors the civic-news sidecar baseline)
- `/etc/plausiden-watchtower/env` — operator env-overrides file (only
  installed if missing; commented template lists every supported var)
- `/var/lib/plausiden-watchtower/` — heartbeat file + AutoClaude
  incident + worktree dirs (owned by the `watchtower` system user)
- `watchtower` system user added to the `systemd-journal` supplementary
  group so the spawned `journalctl -f` subprocesses can see other
  services' logs

After install, edit `/etc/plausiden-watchtower/env` to enable the ntfy
and email sinks, then set up the **external** stale-detector from
`scripts/watchtower-staleness-check.sh` on a separate systemd timer
(see the `Self-monitoring heartbeat (#318)` section above for the
recommended `.timer` recipe). The daemon CANNOT alert on its own
death from inside itself — the external detector is load-bearing.

Tail the daemon:

```sh
journalctl -u plausiden-watchtower -f
```

To remove, pair `deploy/uninstall.sh` with one or more of these env
overrides (idempotent; preserves state + config by default to protect
the AutoClaude incident audit trail):

```sh
# Minimal teardown — stops service, removes binary + unit; preserves
# /var/lib/plausiden-watchtower (incidents + worktrees + heartbeat)
# AND /etc/plausiden-watchtower (operator env file).
sudo ./deploy/uninstall.sh

# Full wipe — also drops state, config, and the system user.
sudo PURGE_STATE=1 PURGE_CONFIG=1 REMOVE_USER=1 ./deploy/uninstall.sh
```

### Path 2 — `flake.nix` + `nixosModules.default`

For NixOS hosts, the flake provides a typed module that mirrors the
systemd unit's hardening flags and exposes the alert sinks as Nix
options:

```nix
{
  inputs.plausiden-watchtower.url = "github:thepictishbeast/plausiden-watchtower";

  outputs = { self, nixpkgs, plausiden-watchtower, ... }: {
    nixosConfigurations.my-vps = nixpkgs.lib.nixosSystem {
      modules = [
        plausiden-watchtower.nixosModules.default
        ({ ... }: {
          services.plausiden-watchtower = {
            enable = true;
            # Sensitive bits — load from a SOPS-nix output or
            # similar; the value is given to systemd as
            # `EnvironmentFile=` so it never lives in the Nix store.
            extraEnvironmentFile = "/run/secrets/plausiden-watchtower.env";

            ntfy = {
              url = "https://ntfy.example.com";
              topic = "sacredvote-watchtower";
            };
            email.to = "ops@example.com";

            autoClaude = {
              enable = false;   # default-OFF; flip carefully.
              rules = [ "fatal_any" "error_burst_per_chain" ];
              projectMap = {
                REGISTRATION = "/srv/sacredvote";
                AUTH = "/srv/sacredvote";
              };
            };
          };
        })
      ];
    };
  };
}
```

`nix flake check` runs build + clippy `--features journal --deny warnings`
+ tests + rustfmt — same gates as the local `deploy/install.sh` path.
