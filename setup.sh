#!/usr/bin/env bash
# GIGACL — one-time setup for Linux and macOS.
#
# Creates the virtual environment, installs the pinned dependencies, and
# prepares .env. Safe to re-run: it upgrades an existing install in place and
# never overwrites an existing .env, because that file holds the key the stored
# switch passwords are encrypted with.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$PROJECT_DIR/venv"
MIN_PY="3.10"

say()  { printf '%s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# ---- Python ---------------------------------------------------------------
PYTHON=""
for candidate in python3.13 python3.12 python3.11 python3.10 python3; do
  if command -v "$candidate" >/dev/null 2>&1; then
    if "$candidate" -c "import sys; raise SystemExit(0 if sys.version_info[:2] >= (3,10) else 1)"; then
      PYTHON="$candidate"; break
    fi
  fi
done
[ -n "$PYTHON" ] || fail "Python $MIN_PY or newer was not found. Install it and run this again."
say "Using $($PYTHON -V) from $(command -v "$PYTHON")"

# python3-venv is a separate package on Debian and Ubuntu, and its absence
# only shows up here, with a message that does not name the package.
"$PYTHON" -c "import venv" 2>/dev/null || \
  fail "The venv module is missing. On Debian/Ubuntu: sudo apt install python3-venv"

# ---- Virtual environment --------------------------------------------------
if [ ! -d "$VENV" ]; then
  say "Creating the virtual environment..."
  "$PYTHON" -m venv "$VENV"
fi

say "Installing dependencies..."
"$VENV/bin/python" -m pip install --quiet --upgrade pip
"$VENV/bin/python" -m pip install --quiet -r "$PROJECT_DIR/requirements.txt"

# ---- Configuration --------------------------------------------------------
if [ ! -f "$PROJECT_DIR/.env" ]; then
  cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
  say "Created .env from the example. The app fills in SECRET_KEY on first start."
else
  say "Keeping the existing .env."
fi
# The key in here decrypts every stored switch password.
chmod 600 "$PROJECT_DIR/.env"

say ""
say "Setup complete. Start the server with:"
say "  ./start.sh"
say ""
say "Then sign in at http://localhost:8000 as 'admin' with the password 'admin'"
say "and change it immediately."
