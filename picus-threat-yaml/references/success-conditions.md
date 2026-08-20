# Success Conditions for Endpoint Modules

This is the **canonical mapping** from an action's intent to the `success_conditions`
block. Endpoint modules (Linux / macOS / Windows / Kubernetes) all use the same
schema.

---

## Two valid shapes

### 1. Output substring match (preferred)

```yaml
play_processes:
  - path: /bin/bash
    arguments: -c "cat /etc/shadow"
    timeout: 15
    success_conditions:
      - output: 'root:'
```

The action is graded as `unblocked` only if the process's stdout contains the
substring `root:`. This catches the common case where the agent blocked the file
read at the syscall level (no output → no substring → `blocked`).

### 2. Exit code match

```yaml
play_processes:
  - path: reg.exe
    arguments: shadowcopy delete
    success_conditions:
      - {}
      - code: 1
        output: No Instance
```

Useful when the underlying command exits non-zero when the target is missing.
The `{}` (empty dict) is a no-op success condition — it always passes.

The skill emits `output:` for read-style actions and `code:` only when the
target is a destructive system command (e.g. `wmic shadowcopy delete`).

---

## The broken pattern

```yaml
success_conditions:
  - code: 0
    is_inverse: false
```

This is what the broken sample uses. It grades every action as `unblocked`
because `code: 0` is the default exit code of `cat` on a readable file. The
agent has no way to differentiate "ran successfully" from "ran but produced no
content". The Picus validator also rejects this when combined with
`is_inverse: false` (the default).

**The skill MUST emit `output:` not `code: 0` for read-style actions.**

---

## PUMAKIT's patterns

The PUMAKIT sample uses these `output:` substrings:

| Action | output |
|---|---|
| `memrun.elf inMemory input.elf` | `root:` |
| `fs_hook` | `PASS` |
| `argv_guardrail` | `Success` |
| `boot_image_dryrun` | `decompressed` |
| `kmod_load` | `removeself` (with `is_inverse: true`) |

The common thread: each substring is a unique string that the simulated binary
will print only when it ran successfully. The substring is NOT a generic
"success" — it is a content marker that proves the code path executed.

---

## Skill defaults

For every read-style action, the skill emits:

```yaml
success_conditions:
  - output: <expected_output>      # from output-patterns.md
```

For destructive system commands, the skill emits:

```yaml
success_conditions:
  - {}
  - code: 1
```

For dropper-script actions, the skill emits:

```yaml
success_conditions:
  - output: <dropper_name>          # the dropper prints its own name
```

This way, if the dropper never ran, the substring is missing and the action
grades as `blocked`. If the dropper ran, the substring is there and the
action grades as `unblocked`.

---

## Fields the skill NEVER emits

- `is_inverse: false` — the default. Always omit.
- `delay: 0` — the default. Always omit.
- `is_async: false` — the default. Always omit.
- `comment:` — not part of the schema. Always omit.
- `success_conditions: []` — always emit at least one condition.

The broken sample sets all of these explicitly. The skill omits them.
