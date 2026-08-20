# Plain-Text Goal Parser

The `scripts/parse_goal.py` parser takes a free-form English description of the
attack goal and produces the same `ActionSpec` list as the SPL/Sigma parsers.
It is the lowest-fidelity path and is intended for one-line intents.

---

## Heuristic

The parser scans the input string for any of the **token patterns** listed in
`references/mappings/linux-targets.md`. For each token that is found, one
`ActionSpec` is emitted. Tokens are matched with the same four-step lookup used
by the SPL parser:

1. Exact substring match — e.g. input "read /etc/shadow" → matches `/etc/shadow`.
2. Substring match — input "tinker with the shadow file" would still match
   `/etc/shadow` if "shadow" appears (the regex is anchored as substring).
3. Regex match — input "all *.ssh files" matches `\.ssh/`.
4. Fallback — input with no recognisable token → single action, fallback row.

The order of tokenization is **longest match first** so that `/etc/shadow-`
beats `/etc/shadow` wins ties.

---

## Examples

| Input | Extracted actions |
|---|---|
| `read /etc/shadow via bash` | 1 action — `/etc/shadow`, shell=bash |
| `enumerate /etc/passwd and /etc/shadow` | 2 actions |
| `read user bash history` | 1 action — `.bash_history` (matched as `\.bash_history`) |
| `dump /proc/net/tcp` | 1 action — `/proc/net/tcp` |
| `read /etc/gshadow` | 1 action — `/etc/gshadow` |
| `find SSH keys` | 1 action — `id_rsa` (first SSH-key match) |
| `list /etc/sudoers.d` | 1 action — `/etc/sudoers.d/` |
| `auditd detection for cat /etc/shadow` | 1 action |
| `read /etc/shadow` | 1 action |

---

## Shell detection

If the goal mentions a shell, the parser uses that. Otherwise it defaults to
`bash`.

Recognized shell keywords:

- `bash`, `/bin/bash`
- `sh`, `/bin/sh`
- `dash`, `/bin/dash`
- `zsh`, `/bin/zsh`
- `ksh`, `/bin/ksh`
- `fish`, `/bin/fish`

If multiple shells are mentioned, the parser emits one action per shell
**for each target** (so "read /etc/shadow via bash and sh" → 2 actions).

---

## What the parser does NOT do

- It does not parse natural language. It does simple substring/regex matching.
- It does not invent targets. If the goal mentions a file not in
  `_TARGET_TABLE`, the fallback row is used and a warning is printed.
- It does not understand "the user said to skip this file" — there is no
  exclusion syntax in plain-text goals.

---

## Pipeline-friendly output

The parser returns the same `ActionSpec` list as SPL and Sigma. It is **fully
interchangeable** with the other parsers downstream — `build_threat.py` does not
know which parser produced the specs.
