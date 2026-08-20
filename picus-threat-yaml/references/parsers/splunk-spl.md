# Splunk SPL Parser

The `scripts/parse_spl.py` parser extracts one `ActionSpec` per target file pattern
embedded in a Splunk SPL rule. It is designed for **auditd EXECVE** queries, which
are the shape most common in Linux endpoint detection.

---

## Heuristic — what we extract

1. **The shell binary** — the value of `a0=` in the SPL. Falls back to `/bin/bash`.
2. **The shell flag** — the value of `a1=` in the SPL. Falls back to `-c`.
3. **The target regex** — the contents of the first `match(...)` (or `regex`) call
   applied to the command line field. The regex usually contains a parenthesized
   alternation group like `(a|b|c|d|e|f)`.
4. **One action per alternation** — each pipe-separated alternative in the
   alternation group becomes a separate `ActionSpec`.

For the user's example SPL:

```
index=os_nix sourcetype=auditd type=EXECVE (a0="sh" OR a0="bash" OR a0="dash") a1="-c"
| where match(execve_command, "/etc/(shadow|passwd|gshadow)|/proc/net/|/\.ssh/|authorized_keys|\.bash_history")
| table _time host uid auid ppid comm exe execve_command
```

We extract:

- **shell binaries**: `["sh", "bash", "dash"]`
- **shell flag**: `-c`
- **target regex**: `/etc/(shadow|passwd|gshadow)|/proc/net/|/\.ssh/|authorized_keys|\.bash_history`
- **alternations in the (outer) group**:
  - `/etc/(shadow|passwd|gshadow)` → expands to 3 alternations: `/etc/shadow`, `/etc/passwd`, `/etc/gshadow`
  - `/proc/net/` → 1 alternation
  - `/\.ssh/` → 1 alternation (matches any ssh directory)
  - `authorized_keys` → 1 alternation
  - `\.bash_history` → 1 alternation
- **total actions**: 7

The `(shadow|passwd|gshadow)` group is auto-expanded because it is rooted at `/etc/`.
Other parens are kept as the user wrote them.

---

## How to interpret the alternation

The parser tokenizes the regex by `|` at the top level (not inside `[...]` or `(...)`).
For each token, it then:

1. Strips leading `^` or trailing `$`.
2. Removes the leading `/` if present.
3. Looks the result up in `references/mappings/linux-targets.md` (or, equivalently,
   the `_TARGET_TABLE` dict in `scripts/build_threat.py`).

If a token is a glob like `/etc/*` or `/etc/<dir>/`, it is kept as-is and the
fallback row is used.

---

## Field extractions

| Field | SPL token | Example |
|---|---|---|
| `shell_path` | `a0="..."` | `a0="bash"` → `/bin/bash` |
| `shell_flag` | `a1="..."` | `a1="-c"` → `-c` |
| `target_regex` | `match(<field>, "<regex>")` or `regex <field>="<regex>"` | `match(execve_command, "/etc/shadow")` |
| `timeout` | hardcoded | `15` (override via `--timeout N`) |

The mapping `bash` → `/bin/bash` lives in `_SHELL_BINARY_MAP` at the top of
`scripts/parse_spl.py`. Supported shortcuts: `bash`, `sh`, `dash`, `zsh`, `ksh`,
`csh`, `tcsh`, `fish`.

---

## What the parser does NOT do

- It does not evaluate the SPL — it only lexes it.
- It does not understand `|` (Splunk pipe) syntax. Pipes separate SPL clauses; the
  parser only cares about the `match()` / `regex` argument that contains the file
  pattern.
- It does not understand `rex` field-extraction commands. If the rule uses `rex`
  instead of `match`, the parser falls back to `_TARGET_TABLE` for any token that
  looks like a path (starts with `/` or contains `.`).

---

## Edge cases

| Input | Parser behavior |
|---|---|
| `match(execve_command, "/etc/shadow")` | 1 action — `/etc/shadow` |
| `match(execve_command, "/etc/(shadow\|passwd)")` | 2 actions — `/etc/shadow`, `/etc/passwd` |
| `match(execve_command, "/etc/(shadow\|passwd\|gshadow)\|/\.ssh/")` | 4 actions |
| `match(execve_command, "\.bash_history")` | 1 action — looks up `.bash_history` |
| `match(execve_command, "(?i)/etc/.*")` | 1 action — fallback / no_priv |
| no `match(` call | parser returns `[]` and the skill errors out |
| multiple `match(` calls | parser concatenates all alternations into one action list |
