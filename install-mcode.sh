#!/usr/bin/env sh
# Install every skill in this repo into MiniMax Code (mcode).
#
#   Skills -> $MINIMAX_HOME/skills/<name>/   (default: ~/.minimax/skills)
#
# A skill is any top-level directory that contains a SKILL.md; its whole
# directory is copied. mcode has no user-level slash-command directory, so a
# skill's commands/ folder is copied with it but is only reachable as the
# skill's own `/<name>` invocation.
#
# mcode also auto-discovers ~/.claude/skills, ~/.codex/skills, ~/.agents/skills
# and the per-workspace .minimax|.claude|.agents/skills (skills.external in
# config.yaml, on by default). Installing here makes the skills mcode-native, so
# they keep working with external discovery turned off or without Claude Code
# installed. A same-named ~/.claude/skills copy still shadows this one (user
# source priority 40 vs global 0) - identical content, so it does not matter.
#
# Usage:
#   ./install-mcode.sh                  install into ~/.minimax (or $MINIMAX_HOME)
#   MINIMAX_HOME=/path ./install-mcode.sh
#   MINIMAX_DATA_DIR=/path ./install-mcode.sh    (same var mcode itself honors)
#   ./install-mcode.sh --dry-run        show what would happen, change nothing
set -eu

REPO_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MINIMAX_HOME=${MINIMAX_HOME:-${MINIMAX_DATA_DIR:-$HOME/.minimax}}
SKILLS_DST="$MINIMAX_HOME/skills"

DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1

log() { printf '%s\n' "$*"; }
run() { if [ "$DRY" -eq 1 ]; then log "  [dry-run] $*"; else "$@"; fi; }

log "Repo:         $REPO_DIR"
log "MiniMax home: $MINIMAX_HOME"
[ "$DRY" -eq 1 ] && log "(dry run - no changes made)"

run mkdir -p "$SKILLS_DST"

count=0
for skill_md in "$REPO_DIR"/*/SKILL.md; do
  [ -e "$skill_md" ] || continue
  skill_dir=$(dirname "$skill_md")
  name=$(basename "$skill_dir")

  # mcode requires frontmatter `name` == directory name, lowercase slug only.
  fm_name=$(sed -n '/^---$/,/^---$/{s/^name:[[:space:]]*//p;}' "$skill_md" | head -1 | tr -d '"'"'" | tr -d '\r')
  if [ "$fm_name" != "$name" ]; then
    log ""
    log "== $name == SKIPPED: frontmatter name '$fm_name' != directory name"
    continue
  fi

  log ""
  log "== $name =="
  run rm -rf "$SKILLS_DST/$name"
  run cp -R "$skill_dir" "$SKILLS_DST/$name"
  log "  skill -> $SKILLS_DST/$name"
  count=$((count + 1))
done

log ""
log "Done. Installed $count skill(s) for mcode."
log "Start a new mcode session to pick them up (/skills lists them)."
