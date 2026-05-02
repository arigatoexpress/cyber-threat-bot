#!/usr/bin/env bash
# Refresh cached threat intel for cyber-threat-bot.
#
# Called every 4 hours by the LaunchAgent at
# infra/com.sapphire.cyber-threat-bot.plist. Writes a fresh JSON snapshot
# to ~/.sapphire/cyber-threat-bot/latest.json so Sapphire plugin tools
# can read it cheaply.
#
# Honors Sapphire's routine pause convention (PR #392): if the file
# ~/.sapphire/routine_pause/cyber-threat-bot exists, this script exits 0
# without doing any work.
set -euo pipefail

REPO_DIR="${CYBER_THREAT_BOT_REPO:-$HOME/Code/cyber-threat-bot}"
STATE_DIR="${CYBER_THREAT_BOT_STATE_DIR:-$HOME/.sapphire/cyber-threat-bot}"
PAUSE_FLAG="$HOME/.sapphire/routine_pause/cyber-threat-bot"

log() { printf '[%s] cyber-threat-bot.refresh %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

if [[ -e "$PAUSE_FLAG" ]]; then
  log "paused via $PAUSE_FLAG; exiting 0"
  exit 0
fi

if [[ ! -d "$REPO_DIR" ]]; then
  log "ERROR: repo not found at $REPO_DIR"
  exit 1
fi

mkdir -p "$STATE_DIR"

# Prefer the editable-install bin if present; otherwise fall back to
# PYTHONPATH=src python -m. This mirrors the dual invocation contract
# the install script enforces.
if [[ -x "$REPO_DIR/.venv/bin/threat-bot" ]]; then
  THREAT_BOT=("$REPO_DIR/.venv/bin/threat-bot")
elif [[ -x "$REPO_DIR/.venv/bin/python" ]]; then
  THREAT_BOT=("$REPO_DIR/.venv/bin/python" -m cyber_threat_bot)
else
  log "WARN: no .venv found at $REPO_DIR; falling back to system python3 + PYTHONPATH"
  export PYTHONPATH="$REPO_DIR/src:${PYTHONPATH:-}"
  THREAT_BOT=("python3" -m cyber_threat_bot)
fi

OUT="$STATE_DIR/latest.json"
TMP="$OUT.tmp.$$"

log "refreshing -> $OUT"
if "${THREAT_BOT[@]}" latest --days 7 --per-source 8 --format json --out "$TMP" >/tmp/cyber-threat-bot.refresh.stdout 2>>/tmp/cyber-threat-bot.refresh.stderr; then
  mv "$TMP" "$OUT"
  log "ok bytes=$(wc -c <"$OUT" | tr -d ' ')"
else
  rc=$?
  rm -f "$TMP"
  log "ERROR: refresh failed with rc=$rc; previous snapshot preserved"
  exit "$rc"
fi
