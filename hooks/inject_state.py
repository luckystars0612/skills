"""
Auto-inject RESEARCH_STATE.md + memory files into Claude context.

Runs as a Claude Code hook (SessionStart / PostCompact).
If the current project has a RESEARCH_STATE.md in its root,
reads it plus all memory files and injects them as additionalContext.
Projects without RESEARCH_STATE.md are silently skipped.
"""
import json, os, sys

try:
    sys.stdin.read()
except:
    pass

state_file = os.path.join(os.getcwd(), 'RESEARCH_STATE.md')

if not os.path.exists(state_file):
    print('{}')
    sys.exit(0)

parts = []

with open(state_file, 'r', encoding='utf-8') as f:
    parts.append(f.read())

def find_memory_dir():
    home = os.path.expanduser('~')
    projects_dir = os.path.join(home, '.claude', 'projects')
    if not os.path.isdir(projects_dir):
        return None
    cwd = os.getcwd()
    sanitized = cwd.replace(':', '-').replace('\\', '-').replace('/', '-')
    if sanitized.startswith('-'):
        sanitized = sanitized[1:]
    for candidate in [sanitized, sanitized[0].lower() + sanitized[1:],
                      sanitized[0].upper() + sanitized[1:]]:
        mem = os.path.join(projects_dir, candidate, 'memory')
        if os.path.isdir(mem):
            return mem
    for entry in os.listdir(projects_dir):
        if entry.lower() == sanitized.lower():
            mem = os.path.join(projects_dir, entry, 'memory')
            if os.path.isdir(mem):
                return mem
    return None

memory_dir = find_memory_dir()
if memory_dir:
    for fname in sorted(os.listdir(memory_dir)):
        if fname.endswith('.md') and fname != 'MEMORY.md':
            fpath = os.path.join(memory_dir, fname)
            with open(fpath, 'r', encoding='utf-8') as f:
                parts.append(f'\n--- {fname} ---\n{f.read()}')

print(json.dumps({
    'hookSpecificOutput': {
        'hookEventName': 'PostCompact',
        'additionalContext': '\n'.join(parts)
    }
}))
