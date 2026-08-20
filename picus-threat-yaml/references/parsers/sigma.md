# Sigma Rule Parser

The `scripts/parse_sigma.py` parser consumes a Sigma rule YAML and extracts one
`ActionSpec` per file/pattern of interest. Sigma rules follow the standard
schema documented at <https://sigmahq.io/docs/basics/rules.html>.

---

## Heuristic

The parser reads the rule as YAML (using PyYAML if available, otherwise a small
stdlib-only loader), then walks the `detection.selection` and
`detection.filter` blocks looking for:

1. **String contains** — `CommandLine|contains: 'foo'` → token `foo`
2. **String contains (any-of)** — `CommandLine|contains|all: ['a', 'b']` → tokens
   `a`, `b`
3. **String ends-with** — `CommandLine|endswith: '/etc/shadow'` → token
   `/etc/shadow`
4. **String starts-with** — `CommandLine|startswith: 'cat'` → token `cat` (used
   only to detect the shell command, not a target)
5. **Regex** — `CommandLine|re: '...'` → the regex is parsed like the SPL
   `match()` case

Tokens are matched against `references/mappings/linux-targets.md` (or the
`_TARGET_TABLE` dict).

---

## Common Sigma fields recognized

| Field | Meaning |
|---|---|
| `title` | The human-readable title — used as the campaign `description`. |
| `id` | The Sigma UUID — used as part of the generated threat name. |
| `description` | Optional; used as campaign `description` if `title` is missing. |
| `logsource.product` | Should be `linux` for the skill to be useful. |
| `logsource.category` | `process_creation` is the most common. |
| `detection.selection` | The primary matching block. |
| `detection.filter` | Optional exclude block — matches are subtracted. |
| `detection.condition` | `selection and not filter` is the standard. |
| `level` | `high`, `medium`, `low` — mapped to campaign `severity`. |

---

## Example Sigma rule (the format we parse)

```yaml
title: Suspicious Access to /etc/shadow via Shell
id: 8e3a9b2c-1234-5678-9abc-def012345678
status: stable
description: Detects shell access to /etc/shadow
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith:
            - /bash
            - /sh
            - /dash
        CommandLine|contains:
            - /etc/shadow
    condition: selection
level: high
```

The parser extracts:

- **shell binaries**: `bash`, `sh`, `dash`
- **target**: `/etc/shadow`
- **count**: 1 action

---

## Multi-pattern Sigma

If `CommandLine|contains` is a list of multiple paths, one action per list entry
is generated:

```yaml
CommandLine|contains:
    - /etc/shadow
    - /etc/passwd
    - /etc/gshadow
```

→ 3 actions.

---

## Regex form

```yaml
CommandLine|re: 'cat\s+/etc/(shadow|passwd)|/\.ssh/authorized_keys'
```

The parser tokenizes identically to the SPL parser: split on `|` at the top level,
expand `(a|b|c)` groups, look each up in `_TARGET_TABLE`.

---

## Filter blocks

`detection.filter` blocks are **ignored** by the parser. The skill trusts the
user's filter logic and emits one action per selection-target. If the user wants
exclusions, they should use the parser's `--exclude` flag instead.

---

## Output

`parse_sigma.py` returns a list of `ActionSpec` objects that look identical to the
SPL output. They all go to the same `build_threat.py` pipeline.
