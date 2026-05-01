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
| ntfy alert sink          | Stubbed  | #316  |
| Email alert sink         | Stubbed  | #316  |
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
cargo run --features journal --release -- \
  --units sacredvote,sacredvote-identity,sacredvote-zktls \
  --ntfy-topic <topic> \
  --email william@plausiden.com
```

The daemon will refuse to start without at least one configured alert sink.

## Building without the journal feature

The parser and classifier libs build on any machine without `libsystemd`:

```sh
cargo build --lib
cargo test --lib
```

This is the path used in CI and on dev laptops.
