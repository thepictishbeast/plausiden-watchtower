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
| Auto-Claude fix loop     | Pending  | #317  |
| Self-monitoring pings    | Pending  | #317  |

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
