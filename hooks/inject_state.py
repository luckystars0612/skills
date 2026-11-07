#!/usr/bin/env python3
"""Inject RESEARCH_STATE.md + prioritized memory files into Claude Code context.

Fires on SessionStart and PostCompact. Projects without RESEARCH_STATE.md are
silently skipped (prints {}).

Priority order for memory files is taken from RESEARCH_STATE.md itself: any
`something.md` mentioned there (in order of appearance) is injected first.
Remaining memory files are listed by name only. Total injection is capped so
session start does not burn tens of thousands of tokens.

IMPORTANT for whoever wires this up: the hook command must pipe Claude Code's
own stdin into this script. Do NOT prefix it with `echo '{}' |` -- that throws
the real payload away, the script never sees `hook_event_name`, and Claude Code
discards the injected context whenever the echoed name does not match the event
that actually fired.
"""
import json, os, sys

BUDGET = 60000          # max chars of memory-file bodies (~15k tokens)
NOTHING = '{}'

def log(msg):
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'inject_state.log'), 'a', encoding='utf-8') as f:
            f.write(msg + '\n')
    except Exception:
        pass

# ---- 1. event name: must echo back the event we were actually called for ----
event = 'SessionStart'
try:
    raw = sys.stdin.read()
    if raw.strip():
        event = json.loads(raw).get('hook_event_name') or event
except Exception as e:
    log('stdin parse failed: %r' % (e,))

cwd = os.getcwd()
state_file = os.path.join(cwd, 'RESEARCH_STATE.md')
if not os.path.exists(state_file):
    print(NOTHING)
    sys.exit(0)

with open(state_file, 'r', encoding='utf-8', errors='replace') as f:
    state = f.read()

# ---- 2. locate the memory dir for this project ----
def find_memory_dir():
    projects_dir = os.path.join(os.path.expanduser('~'), '.claude', 'projects')
    if not os.path.isdir(projects_dir):
        return None
    sanitized = cwd.replace(':', '-').replace(chr(92), '-').replace('/', '-').lstrip('-')
    direct = os.path.join(projects_dir, sanitized, 'memory')
    if os.path.isdir(direct):
        return direct
    for entry in os.listdir(projects_dir):
        if entry.lower() == sanitized.lower():
            mem = os.path.join(projects_dir, entry, 'memory')
            if os.path.isdir(mem):
                return mem
    return None

parts = [state]
memory_dir = find_memory_dir()

if memory_dir:
    import re
    available = sorted(fn for fn in os.listdir(memory_dir)
                       if fn.endswith('.md') and fn != 'MEMORY.md')
    # files named in RESEARCH_STATE.md, in order of first mention
    priority, seen = [], set()
    for m in re.findall(r'[\w.-]+\.md', state):
        if m in available and m not in seen:
            seen.add(m); priority.append(m)
    ordered = priority + [fn for fn in available if fn not in seen]

    used, included, skipped = 0, [], []
    for fn in ordered:
        path = os.path.join(memory_dir, fn)
        try:
            size = os.path.getsize(path)
            if used + size > BUDGET:
                skipped.append('%s (%dKB)' % (fn, size // 1024))
                continue
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                parts.append('\n--- %s ---\n%s' % (fn, f.read()))
            used += size; included.append(fn)
        except Exception as e:
            log('read %s failed: %r' % (fn, e))

    if skipped:
        parts.append('\n--- not injected (read on demand from %s) ---\n%s'
                     % (memory_dir, '\n'.join('- ' + s for s in skipped)))
    log('%s: injected %d/%d memory files, %d chars' %
        (event, len(included), len(available), used))
else:
    parts.append('\n[inject_state: no memory dir found for %s]' % cwd)
    log('%s: no memory dir for %s' % (event, cwd))

print(json.dumps({'hookSpecificOutput': {
    'hookEventName': event,
    'additionalContext': '\n'.join(parts),
}}))
