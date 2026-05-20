#!/usr/bin/env bash
#
# scripts/ci.sh — Local CI gate for plausiden-watchtower.
#
# Runs the full pre-commit / pre-push battery. Exit 0 = ship; exit 1
# = something broken.
#
# Sibling artifact to sacredvote-axum-poc/scripts/ci.sh (LOOP-V3.1#207).
# Same 5-gate shape across all in-scope Rust crates so operators get
# consistent ship-readiness signals regardless of which repo.
#
# Gates:
#   1. cargo fmt --check     — formatting clean
#   2. cargo build --features journal  — compiles WITH journal tailer
#                                        (the production feature set;
#                                        prod refuses to start without it)
#   3. cargo clippy --all-targets --features journal  — no lints
#   4. cargo test --features journal --quiet  — full suite passes,
#                                               INCLUDING the journal-
#                                               gated tests (otherwise
#                                               4 of the 67 tests skip)
#   5. cargo audit           — no known-vulnerable crates in Cargo.lock
#
# Why `--features journal` on the test gate specifically:
# watchtower's binary refuses to start without the journal feature
# (per its install.sh + flake.nix); a test run WITHOUT --features
# would skip the production code path. CI must mirror prod.

set -euo pipefail

if [[ ! -f Cargo.toml ]]; then
  echo "FATAL: must run from plausiden-watchtower repo root" >&2
  exit 2
fi

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
hdr()   { printf '\n\033[1;36m═══ %s ═══\033[0m\n' "$*"; }

failures=0
ran=0

run_gate() {
  local name="$1"
  shift
  ran=$((ran + 1))
  hdr "Gate ${ran}: ${name}"
  if "$@"; then
    green "  ✓ ${name} passed"
  else
    red "  ✗ ${name} FAILED"
    failures=$((failures + 1))
  fi
}

run_gate "cargo fmt --check" cargo fmt --check
run_gate "cargo build --features journal" cargo build --features journal
run_gate "cargo clippy --all-targets --features journal" cargo clippy --all-targets --features journal
run_gate "cargo test --features journal --quiet" cargo test --features journal --quiet
run_gate "cargo audit" cargo audit

echo ""
if [[ "${failures}" -eq 0 ]]; then
  green "════════════════════════════════════════"
  green "  ALL ${ran} GATES PASSED — safe to commit/push"
  green "════════════════════════════════════════"
  exit 0
else
  red "════════════════════════════════════════"
  red "  ${failures} / ${ran} GATES FAILED — DO NOT push"
  red "════════════════════════════════════════"
  exit 1
fi
