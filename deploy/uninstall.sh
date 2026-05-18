#!/usr/bin/env bash
# Uninstall plausiden-watchtower.
#
# Idempotent: safe to run when partially or fully installed.
# Preserves /var/lib/plausiden-watchtower (heartbeat + incident
# transcripts + AutoClaude worktrees) AND /etc/plausiden-watchtower
# (operator env file) by default. Override:
#   PURGE_STATE=1    rm -rf /var/lib/plausiden-watchtower
#                    (drops auto-claude incident audit trail!)
#   PURGE_CONFIG=1   rm -rf /etc/plausiden-watchtower
#                    (drops operator env file)
#   REMOVE_USER=1    userdel `watchtower`
#
# Requires: root.

set -euo pipefail

INSTALL_PREFIX="${INSTALL_PREFIX:-/opt/plausiden-watchtower}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
SERVICE_USER="${SERVICE_USER:-watchtower}"
STATE_DIR="${STATE_DIR:-/var/lib/plausiden-watchtower}"
CONFIG_DIR="${CONFIG_DIR:-/etc/plausiden-watchtower}"
SERVICE_NAME="plausiden-watchtower.service"

PURGE_STATE="${PURGE_STATE:-0}"
PURGE_CONFIG="${PURGE_CONFIG:-0}"
REMOVE_USER="${REMOVE_USER:-0}"

if [[ "$(id -u)" != "0" ]]; then
  echo "must run as root" >&2
  exit 1
fi

echo "[uninstall] plausiden-watchtower teardown"
echo "[uninstall] PURGE_STATE=${PURGE_STATE} PURGE_CONFIG=${PURGE_CONFIG} REMOVE_USER=${REMOVE_USER}"

# Stop + disable the service if present.
if systemctl list-unit-files --no-pager 2>/dev/null | grep -q "^${SERVICE_NAME}"; then
  echo "[uninstall] stopping ${SERVICE_NAME}"
  systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
  echo "[uninstall] disabling ${SERVICE_NAME}"
  systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
else
  echo "[uninstall] service ${SERVICE_NAME} not installed; skipping stop/disable"
fi

# Remove unit file + reload.
if [[ -f "${SYSTEMD_DIR}/${SERVICE_NAME}" ]]; then
  echo "[uninstall] removing ${SYSTEMD_DIR}/${SERVICE_NAME}"
  rm -f "${SYSTEMD_DIR}/${SERVICE_NAME}"
  systemctl daemon-reload
fi

# Remove the binary install tree.
if [[ -d "${INSTALL_PREFIX}" ]]; then
  echo "[uninstall] removing ${INSTALL_PREFIX}"
  rm -rf "${INSTALL_PREFIX}"
fi

# Optionally remove state (incident transcripts, worktrees, heartbeat).
# Preserved by default — losing the auto-claude incident log would
# kill the operator's only record of what Claude did during fix runs.
if [[ "${PURGE_STATE}" == "1" ]]; then
  if [[ -d "${STATE_DIR}" ]]; then
    echo "[uninstall] PURGE_STATE=1 — removing ${STATE_DIR}"
    echo "[uninstall]   WARNING: this drops auto-claude incident transcripts"
    rm -rf "${STATE_DIR}"
  fi
else
  echo "[uninstall] preserving ${STATE_DIR} (set PURGE_STATE=1 to remove)"
fi

# Optionally remove the operator env file + config dir.
if [[ "${PURGE_CONFIG}" == "1" ]]; then
  if [[ -d "${CONFIG_DIR}" ]]; then
    echo "[uninstall] PURGE_CONFIG=1 — removing ${CONFIG_DIR}"
    rm -rf "${CONFIG_DIR}"
  fi
else
  echo "[uninstall] preserving ${CONFIG_DIR} (set PURGE_CONFIG=1 to remove)"
fi

# Optionally remove the system user. Idempotent: userdel of a
# nonexistent user is silently ignored.
if [[ "${REMOVE_USER}" == "1" ]]; then
  if id "${SERVICE_USER}" >/dev/null 2>&1; then
    echo "[uninstall] REMOVE_USER=1 — removing user ${SERVICE_USER}"
    userdel "${SERVICE_USER}" 2>/dev/null || true
  fi
else
  echo "[uninstall] preserving user ${SERVICE_USER} (set REMOVE_USER=1 to remove)"
fi

echo "[uninstall] done."
