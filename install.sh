#!/usr/bin/env sh
# Install every skill in this repo (plus its slash commands) into Claude Code.
#
#   Skills   -> $CLAUDE_HOME/skills/<name>/     (default: ~/.claude/skills)
#   Commands -> $CLAUDE_HOME/commands/<cmd>.md   (default: ~/.claude/commands)
#
# A skill is any top-level directory that contains a SKILL.md. Its whole
# directory is copied under skills/, and any commands/*.md (except README.md)
# is also dropped into commands/ so the /<name> slash command works.
#
# Usage:
#   ./install.sh                 install into ~/.claude (or $CLAUDE_HOME)
#   CLAUDE_HOME=/path ./install.sh
#   ./install.sh --dry-run       show what would happen, change nothing
set -eu

REPO_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CLAUDE_HOME=${CLAUDE_HOME:-$HOME/.claude}
SKILLS_DST="$CLAUDE_HOME/skills"
CMDS_DST="$CLAUDE_HOME/commands"

DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1

log() { printf '%s\n' "$*"; }
run() { if [ "$DRY" -eq 1 ]; then log "  [dry-run] $*"; else "$@"; fi; }

log "Repo:        $REPO_DIR"
log "Claude home: $CLAUDE_HOME"
[ "$DRY" -eq 1 ] && log "(dry run - no changes made)"

run mkdir -p "$SKILLS_DST" "$CMDS_DST"

count=0
for skill_md in "$REPO_DIR"/*/SKILL.md; do
  [ -e "$skill_md" ] || continue
  skill_dir=$(dirname "$skill_md")
  name=$(basename "$skill_dir")
  log ""
  log "== $name =="

  # 1) install the whole skill directory
  run rm -rf "$SKILLS_DST/$name"
  run cp -R "$skill_dir" "$SKILLS_DST/$name"
  log "  skill   -> $SKILLS_DST/$name"

  # 2) install its slash commands (skip README.md)
  if [ -d "$skill_dir/commands" ]; then
    for cmd in "$skill_dir"/commands/*.md; do
      [ -e "$cmd" ] || continue
      base=$(basename "$cmd")
      [ "$base" = "README.md" ] && continue
      run cp "$cmd" "$CMDS_DST/$base"
      log "  command -> $CMDS_DST/$base"
    done
  fi

  count=$((count + 1))
done

log ""
log "Done. Installed $count skill(s)."
log "Start a new Claude Code session (or restart) to pick them up."
