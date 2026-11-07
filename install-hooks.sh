#!/usr/bin/env sh
# Install Claude Code hooks (research state auto-restore).
#
#   Scripts -> $CLAUDE_HOME/scripts/         (default: ~/.claude/scripts)
#   Hooks   -> merged into ~/.claude/settings.json
#
# Installs inject_state.py and adds PostCompact + SessionStart hooks
# so RESEARCH_STATE.md is auto-injected after compaction / session start.
#
# Usage:
#   ./install-hooks.sh                install
#   ./install-hooks.sh --dry-run      show what would happen
#   ./install-hooks.sh --uninstall    remove hooks and script
set -eu

REPO_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CLAUDE_HOME=${CLAUDE_HOME:-$HOME/.claude}
SCRIPTS_DST="$CLAUDE_HOME/scripts"
SETTINGS="$CLAUDE_HOME/settings.json"
SCRIPT_NAME="inject_state.py"
SCRIPT_SRC="$REPO_DIR/hooks/$SCRIPT_NAME"

DRY=0; UNINSTALL=0
[ "${1:-}" = "--dry-run" ] && DRY=1
[ "${1:-}" = "--uninstall" ] && UNINSTALL=1

log() { printf '%s\n' "$*"; }
run() { if [ "$DRY" -eq 1 ]; then log "  [dry-run] $*"; else "$@"; fi; }

log "Repo:        $REPO_DIR"
log "Claude home: $CLAUDE_HOME"
[ "$DRY" -eq 1 ] && log "(dry run - no changes made)"

# --- Uninstall ---
if [ "$UNINSTALL" -eq 1 ]; then
    target="$SCRIPTS_DST/$SCRIPT_NAME"
    if [ -f "$target" ]; then
        run rm "$target"
        log "  removed $target"
    fi
    if [ -f "$SETTINGS" ] && command -v python3 >/dev/null 2>&1; then
        if [ "$DRY" -eq 1 ]; then
            log "  [dry-run] remove hooks from settings.json"
        else
            python3 -c "
import json
with open('$SETTINGS','r') as f: s=json.load(f)
h=s.get('hooks',{})
h.pop('PostCompact',None); h.pop('SessionStart',None)
if not h: s.pop('hooks',None)
with open('$SETTINGS','w') as f: json.dump(s,f,indent=2)
"
            log "  removed hooks from settings.json"
        fi
    fi
    log ""; log "Done. Hooks uninstalled."
    exit 0
fi

# --- Install script ---
run mkdir -p "$SCRIPTS_DST"
if [ "$DRY" -eq 1 ]; then log "  [dry-run] copy $SCRIPT_NAME -> $SCRIPTS_DST/"; else
    cp "$SCRIPT_SRC" "$SCRIPTS_DST/$SCRIPT_NAME"
    log "  script -> $SCRIPTS_DST/$SCRIPT_NAME"
fi

# --- Merge hooks into settings.json ---
if [ "$DRY" -eq 1 ]; then
    log "  [dry-run] merge hooks into settings.json"
else
    python3 -c "
import json, os

settings_path = '$SETTINGS'
if os.path.exists(settings_path):
    with open(settings_path, 'r') as f:
        settings = json.load(f)
else:
    settings = {}

# NOTE: no 'echo {} |' prefix -- the script must receive Claude Code's
# real stdin payload so it can read hook_event_name and echo it back.
hook_cmd = 'python -I \"\$HOME/.claude/scripts/inject_state.py\" 2>/dev/null || echo \\'{}\\''

hooks = settings.setdefault('hooks', {})
hooks['PostCompact'] = [{
    'matcher': 'auto',
    'hooks': [{
        'type': 'command',
        'command': hook_cmd,
        'timeout': 10,
        'statusMessage': 'Restoring research state...'
    }]
}]
hooks['SessionStart'] = [{
    'hooks': [{
        'type': 'command',
        'command': hook_cmd,
        'timeout': 10,
        'statusMessage': 'Loading research state...'
    }]
}]

with open(settings_path, 'w') as f:
    json.dump(settings, f, indent=2)
"
    log "  hooks  -> $SETTINGS"
fi

log ""
log "Done. Hooks installed."
log "Any project with a RESEARCH_STATE.md in its root will auto-restore context."
log "Restart Claude Code to pick up the new hooks."
