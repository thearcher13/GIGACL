#!/usr/bin/env bash
# GIGACL — stop the server started by start.sh.
#   ./stop.sh              stops the server on port 8000
#   PORT=8080 ./stop.sh    stops the server on another port
set -euo pipefail

PORT="${PORT:-8000}"

# Match on the listening socket, not on a name. `pkill -f uvicorn` also matches
# the shell that ran it and any editor with the word on screen, which is a good
# way to kill the wrong thing.
PIDS="$(ss -ltnpH "sport = :$PORT" 2>/dev/null | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u || true)"

if [ -z "$PIDS" ]; then
  echo "Nothing is listening on port $PORT."
  exit 0
fi

for pid in $PIDS; do
  # Confirm it is ours before signalling it: another service on this port is
  # somebody else's, and stopping it is not this script's business.
  if tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -q "uvicorn main:app"; then
    kill "$pid" && echo "Stopped GIGACL (PID $pid) on port $PORT."
  else
    echo "Port $PORT is held by PID $pid, which is not GIGACL. Nothing stopped." >&2
    exit 3
  fi
done
