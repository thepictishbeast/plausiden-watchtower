#!/usr/bin/env bash
# Install plausiden-watchtower as a systemd service.
#
# Idempotent: re-running just refreshes the binary + restarts the
# service. Safe to run after a `git pull` to pick up new code.
#
# Requires:
#   - cargo + Rust toolchain on PATH (for the release build)
#   - root (for systemd install + user creation + /etc + /opt + /var)
#   - `journal` feature is built by default; the binary refuses to
#     start without it (the daemon needs the journalctl tailer)
#
# Env overrides (rarely needed):
#   INSTALL_PREFIX     default /opt/plausiden-watchtower
#   SYSTEMD_DIR        default /etc/systemd/system
#   SERVICE_USER       default watchtower
#   ENV_FILE           default /etc/plausiden-watchtower/env
#   STATE_DIR          default /var/lib/plausiden-watchtower
#
# Pair with deploy/uninstall.sh (see companion script) to fully
# remove. By default uninstall preserves state + config; set
# PURGE_STATE=1 / PURGE_CONFIG=1 / REMOVE_USER=1 to wipe.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL_PREFIX="${INSTALL_PREFIX:-/opt/plausiden-watchtower}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
SERVICE_USER="${SERVICE_USER:-watchtower}"
ENV_FILE="${ENV_FILE:-/etc/plausiden-watchtower/env}"
STATE_DIR="${STATE_DIR:-/var/lib/plausiden-watchtower}"

if [[ "$(id -u)" != "0" ]]; then
  echo "must run as root" >&2
  exit 1
fi

echo "[install] building release binary with journal feature"
cd "${REPO_ROOT}"
cargo build --release --features journal

echo "[install] creating service user ${SERVICE_USER} if absent"
if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
  useradd --system --shell /usr/sbin/nologin --home-dir /nonexistent "${SERVICE_USER}"
fi

# systemd-journal supplementary group lets the spawned `journalctl -f`
# subprocesses see other services' logs (sacredvote, sacredvote-identity,
# etc.). Without this the daemon starts but the tailer reads nothing.
if getent group systemd-journal >/dev/null 2>&1; then
  if ! id -nG "${SERVICE_USER}" | tr ' ' '\n' | grep -qx systemd-journal; then
    echo "[install] adding ${SERVICE_USER} to systemd-journal group"
    usermod -aG systemd-journal "${SERVICE_USER}"
  fi
else
  echo "[install] warning: systemd-journal group not present; journal tailer will see only this unit's own messages" >&2
fi

echo "[install] installing binary to ${INSTALL_PREFIX}/bin/"
install -d "${INSTALL_PREFIX}/bin"
install -m 0755 "${REPO_ROOT}/target/release/plausiden-watchtower" \
  "${INSTALL_PREFIX}/bin/plausiden-watchtower"

echo "[install] preparing state dir ${STATE_DIR}"
install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0755 "${STATE_DIR}"
# Auto-claude default incident + worktree subdirs (operator can override
# via WATCHTOWER_AUTO_CLAUDE_INCIDENT_DIR / _WORKTREE_BASE).
install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0755 \
  "${STATE_DIR}/incidents" "${STATE_DIR}/worktrees"

echo "[install] preparing env file ${ENV_FILE} (only if missing)"
install -d "$(dirname "${ENV_FILE}")"
if [[ ! -f "${ENV_FILE}" ]]; then
  cat >"${ENV_FILE}" <<'EOT'
# plausiden-watchtower runtime env. Override systemd-unit defaults
# here. Lines starting with `#` are comments. KEY=value, no quotes.
#
# === Alerting sinks (all default-OFF unless these are set) ===
#
# ntfy push to your phone:
# NTFY_URL=http://127.0.0.1:8090
# WATCHTOWER_NTFY_TOPIC=sacredvote-watchtower
# NTFY_TOKEN=...                              # required against prod ntfy
# WATCHTOWER_NTFY_RATE_PER_MIN=10              # token-bucket cap
#
# Email (Page severity only; 4/day cap; 6h per-(rule,key) dedup):
# WATCHTOWER_EMAIL_TO=ops@example.com
# WATCHTOWER_EMAIL_FROM=alerts@sacredvote.org # NEVER tim@sacred.vote
# WATCHTOWER_EMAIL_BIN=mail
#
# === AutoClaude fix loop (#317) — STRICTLY DEFAULT-OFF ===
# WATCHTOWER_AUTO_CLAUDE_ENABLE=1
# WATCHTOWER_AUTO_CLAUDE_RULES=fatal_any,error_burst_per_chain
# WATCHTOWER_AUTO_CLAUDE_PROJECT_REGISTRATION=/srv/sacredvote
# WATCHTOWER_AUTO_CLAUDE_PROJECT_AUTH=/srv/sacredvote
# WATCHTOWER_AUTO_CLAUDE_MAX_CONCURRENT=1
EOT
  chmod 0640 "${ENV_FILE}"
fi

echo "[install] installing systemd unit"
install -m 0644 "${REPO_ROOT}/deploy/systemd/plausiden-watchtower.service" \
  "${SYSTEMD_DIR}/plausiden-watchtower.service"

echo "[install] daemon-reload + enable + restart"
systemctl daemon-reload
systemctl enable plausiden-watchtower.service
systemctl restart plausiden-watchtower.service

echo "[install] done. Tail status:"
systemctl --no-pager status plausiden-watchtower.service | head -20

cat <<'NEXT'

[install] Next steps:
  1. Edit /etc/plausiden-watchtower/env to enable alert sinks.
  2. Set up an EXTERNAL stale-detector cron/timer using
     scripts/watchtower-staleness-check.sh — the daemon CANNOT
     alert on its own death from inside itself.
  3. Watch:   journalctl -u plausiden-watchtower -f
NEXT
