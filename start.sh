#!/usr/bin/env bash
# GIGACL — start script for Linux and macOS.
#
#   ./start.sh                 http on 0.0.0.0:8000
#   PORT=8080 ./start.sh       a different port
#   RELOAD=1 ./start.sh        development: restart on every backend save
#   PROXY=1 ./start.sh         behind nginx/Apache: trust the forwarded client IP
#
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$PROJECT_DIR/venv"
HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8000}"

# First run, or a checkout that has never been set up.
if [ ! -x "$VENV/bin/python" ]; then
  echo "No virtual environment yet — running setup..."
  "$PROJECT_DIR/setup.sh"
fi

# A dependency added since the last install shows up here rather than as an
# ImportError three screens into the boot log.
if ! "$VENV/bin/python" -c "import uvicorn, fastapi, netmiko" >/dev/null 2>&1; then
  echo "Installing missing dependencies..."
  "$VENV/bin/python" -m pip install --quiet -r "$PROJECT_DIR/requirements.txt"
fi

ARGS=()

# Opt-in auto-restart for development. Off by default: reload watches the
# whole tree and restarts on every save, which is the wrong behaviour for a
# server people are actually using. With it off, remember that editing
# anything under backend/ needs this script restarted before the change is
# live -- a stale process serves the old code and looks like a bug in the new.
if [ -n "${RELOAD:-}" ]; then
  ARGS+=(--reload --reload-dir "$PROJECT_DIR/backend")
  echo "Auto-restart is ON (RELOAD is set); backend edits apply immediately."
fi

# Behind a reverse proxy, the address that connected to us is the proxy. The
# app reads request.client.host for the trusted-hosts check and for every audit
# entry, so without this every user would be recorded as 127.0.0.1 and a
# per-IP allow list would either admit everyone or nobody. --forwarded-allow-ips
# is what keeps that safe: the forwarded header is honoured only when the hop
# we are actually talking to is the local proxy, so a remote client cannot
# claim an address by setting the header itself.
if [ -n "${PROXY:-}" ]; then
  ARGS+=(--proxy-headers --forwarded-allow-ips "${FORWARDED_ALLOW_IPS:-127.0.0.1}")
  echo "Proxy mode is ON; client addresses come from the local reverse proxy."
fi

# Deliberately one worker. Live SSH sessions, the switch terminal's channels
# and the per-user connection pool all live in this process's memory, and
# SQLite takes one writer at a time. A second worker would answer half the
# requests without any of that state and corrupt the rest.
echo "Starting GIGACL on http://${HOST}:${PORT}"
echo "Press Ctrl+C to stop."
echo

cd "$PROJECT_DIR/backend"
exec "$VENV/bin/python" -m uvicorn main:app \
  --host "$HOST" --port "$PORT" --workers 1 "${ARGS[@]}"
