#!/usr/bin/env bash
# plausiden-watchtower: external heartbeat-staleness detector.
#
# The watchtower daemon writes a heartbeat file every interval (default
# 60s). If the daemon dies, the file's mtime stops advancing — but the
# daemon itself can't alert on its own death. This script is the
# fallback: run from a separate systemd timer (or cron) every minute or
# two; pages via ntfy if the heartbeat file is missing OR older than
# WATCHTOWER_HEARTBEAT_STALE_SECS (default 300s / 5min, matching the
# README spec "absence of ping for >5 min triggers a fallback ntfy").
#
# Exits 0 on success/healthy, 1 on alert-fired, 2 on misconfig.
#
# Reads the SAME env vars the daemon uses (NTFY_URL, WATCHTOWER_NTFY_TOPIC,
# NTFY_TOKEN) so a single systemd EnvironmentFile= covers both units.
# Does NOT parse the heartbeat file body — only its mtime — so the
# Rust side is free to evolve the body format without breaking this
# detector.

set -u

HEARTBEAT_PATH="${WATCHTOWER_HEARTBEAT_PATH:-/var/lib/plausiden-watchtower/heartbeat}"
THRESHOLD_SECS="${WATCHTOWER_HEARTBEAT_STALE_SECS:-300}"
NTFY_URL="${NTFY_URL:-}"
NTFY_TOPIC="${WATCHTOWER_NTFY_TOPIC:-sacredvote-watchtower}"
NTFY_TOKEN="${NTFY_TOKEN:-}"

if [[ -z "${NTFY_URL}" ]]; then
  echo "watchtower-staleness-check: NTFY_URL not set — cannot alert" >&2
  exit 2
fi

if ! [[ "${THRESHOLD_SECS}" =~ ^[0-9]+$ ]] || (( THRESHOLD_SECS < 60 )); then
  echo "watchtower-staleness-check: WATCHTOWER_HEARTBEAT_STALE_SECS must be integer >=60 (got: ${THRESHOLD_SECS})" >&2
  exit 2
fi

if [[ ! -e "${HEARTBEAT_PATH}" ]]; then
  reason="missing"
  age="unknown"
elif [[ ! -f "${HEARTBEAT_PATH}" ]]; then
  echo "watchtower-staleness-check: ${HEARTBEAT_PATH} exists but is not a regular file" >&2
  exit 2
else
  mtime=$(stat -c %Y "${HEARTBEAT_PATH}" 2>/dev/null || echo 0)
  now=$(date +%s)
  age=$(( now - mtime ))
  if (( age < THRESHOLD_SECS )); then
    # Healthy — heartbeat fresh.
    exit 0
  fi
  reason="stale"
fi

msg="Watchtower heartbeat ${reason} (age=${age}s, threshold=${THRESHOLD_SECS}s, path=${HEARTBEAT_PATH}). Investigate: systemctl status plausiden-watchtower"

curl_args=(
  -fsS
  -X POST
  -H "Title: Watchtower silent"
  -H "Priority: urgent"
  -H "Tags: rotating_light"
)
if [[ -n "${NTFY_TOKEN}" ]]; then
  curl_args+=( -H "Authorization: Bearer ${NTFY_TOKEN}" )
fi

if curl "${curl_args[@]}" \
     "${NTFY_URL%/}/${NTFY_TOPIC}" \
     -d "${msg}" >/dev/null; then
  echo "watchtower-staleness-check: alerted — ${msg}" >&2
  exit 1
else
  echo "watchtower-staleness-check: alert FAILED (curl error) — ${msg}" >&2
  exit 2
fi
