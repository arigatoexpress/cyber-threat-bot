#!/usr/bin/env bash
# Reliable editable install for cyber-threat-bot.
#
# Why this exists
# ----------------
# On many developer Macs, `pip` and `python3` resolve to *different* Python
# interpreters (e.g. system framework Python 3.13 ships its own pip, while
# Homebrew links `python3` to 3.14). Plain `pip install -e .` then installs
# into a site-packages that `python3 -m cyber_threat_bot ...` cannot see,
# leaving the package importable for one interpreter but invisible to the
# other. Worse, the `threat-bot` script lands in a bin directory that's
# not on PATH, and CI sometimes papers over this with PYTHONPATH=src.
#
# This script always installs into a project-local `.venv` using
# `<interpreter> -m pip` (never bare `pip`), so the bin directory and the
# importing interpreter agree by construction. After this runs, BOTH of
# these work:
#
#   .venv/bin/threat-bot latest --days 7
#   .venv/bin/python -m cyber_threat_bot latest --days 7
#
# And the legacy invocation also still works for anyone who keeps it:
#
#   PYTHONPATH=src .venv/bin/python -m cyber_threat_bot latest --days 7
#
# Usage
# -----
#   ./scripts/install.sh                # creates/updates .venv with package
#   ./scripts/install.sh --with-dev     # also installs dev extras
#   ./scripts/install.sh --with-http    # also installs http extras (fastapi)
#   ./scripts/install.sh --python 3.12  # use a specific interpreter
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python3}"
EXTRAS=()
VENV_DIR=".venv"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-dev)  EXTRAS+=("dev"); shift ;;
    --with-http) EXTRAS+=("http"); shift ;;
    --python)    PYTHON_BIN="python${2}"; shift 2 ;;
    --venv)      VENV_DIR="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,28p' "$0"; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "ERROR: $PYTHON_BIN not found. Install Python 3.11+ or pass --python 3.12." >&2
  exit 1
fi

# Always create venv with the chosen interpreter so its `bin/python` IS the
# install target. Never trust ambient `pip`.
if [[ ! -x "$VENV_DIR/bin/python" ]]; then
  echo "Creating venv at $VENV_DIR using $PYTHON_BIN ..."
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

VENV_PY="$VENV_DIR/bin/python"

# Use the venv's own python -m pip, never bare `pip`. This avoids the
# system pip / python3 split that was the original gotcha.
"$VENV_PY" -m pip install --upgrade pip wheel >/dev/null

INSTALL_TARGET="."
if [[ ${#EXTRAS[@]} -gt 0 ]]; then
  EXTRAS_JOINED=$(IFS=,; echo "${EXTRAS[*]}")
  INSTALL_TARGET=".[${EXTRAS_JOINED}]"
fi

echo "Installing $INSTALL_TARGET (editable) into $VENV_DIR ..."
"$VENV_PY" -m pip install -e "$INSTALL_TARGET"

echo
echo "Verifying install ..."
"$VENV_PY" -c "import cyber_threat_bot; print(' import OK:', cyber_threat_bot.__file__)"
"$VENV_DIR/bin/threat-bot" --help >/dev/null && echo " threat-bot CLI: OK"
echo
echo "Done. Activate with:  source $VENV_DIR/bin/activate"
echo "Or call directly:     $VENV_DIR/bin/threat-bot latest --days 7"
