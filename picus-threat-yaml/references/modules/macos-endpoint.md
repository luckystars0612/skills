# macOS Endpoint Scenario Module Reference

`module: macOS Endpoint Scenario`

**Canonical example to use as a template:**

- [Realst Infostealer Campaign](../../../Desktop/picus-threats/Realst%20Infostealer%20Campaign/threat.yaml) — 7 actions across Discovery → Credential Access → Collection

---

## Module invariants (consistent across every macOS Endpoint action)

| Field | Value | Notes |
|---|---|---|
| `module` | `macOS Endpoint Scenario` (literal — lowercase `macOS`) | campaign-level |
| `severity` | `High` | only severity seen |
| `affected_os` | `[- macOS]` (mixed case) | always |
| `affected_platforms` | 5-entry macOS block (Tahoe, Sonoma, Ventura, Sequoia, Monterey) | every action carries this exact block |
| `is_atomic` | `true` | always |
| `category` | `Attack Scenario` | always literal |
| `ukc_phase` | varies | Discovery, Credential Access, Collection, Execution, … |
| `tactic` / `technique` / `sub_technique` | MITRE IDs | optional `sub_technique` |
| `description` | inline string (NOT ` ` | `-` block) | stylistic — keep on one line |
| `title` | **absent** | unlike other Endpoint modules, macOS actions don't use `title` |
| `is_applicable_to_all_platforms` | optional | present (`true`) on simpler actions, omitted on actions using `remote_files` |
| `is_privileged` | optional | `true` on credential-access actions |

**macOS-specific `keyword_queries` noise filter** — distinct from Linux:

```
AND NOT (("rm" AND " -rf") OR "com.apple.quarantine" OR "PICUS_REWIND")
```

The `com.apple.quarantine` token is the macOS-specific signal; `PICUS_REWIND` is the Picus-internal rewind marker.

---

## macOS `affected_platforms` block (the 5-entry canonical list)

```yaml
affected_platforms:
    - name: MacOS 26 Tahoe
      architecture: 64-bit
    - name: MacOS 14 Sonoma
      architecture: 64-bit
    - name: MacOS 13 Ventura
      architecture: 64-bit
    - name: MacOS 15 Sequoia
      architecture: 64-bit
    - name: MacOS 12 Monterey
      architecture: 64-bit
```

All 64-bit, all `architecture: 64-bit`. No arm64, no Intel distinction. Newest release first (Tahoe is at the top of the list).

---

## Campaign-level shape

```yaml
campaign:
    name: <Malware Family> Campaign                # e.g. Realst Infostealer Campaign
    description: <one-line blurb>
    module: macOS Endpoint Scenario
    severity: High
    affected_os:
        - macOS
    result_condition:                              # Operator: and (vs K8s's 'or')
        true: unblocked
        false: blocked
        condition:
            Terms:
                - Right: {Value: unblocked}
                  Left:  {Value: '%objective-1%'}
                  Operator: eq
                # ... up to '%objective-N%'
            Operator: and
    objectives:
        # ...
```

---

## Objective-level shape

```yaml
- type: <UKC phase>            # Discovery | Credential Access | Collection | Execution | …
  result_condition:            # single eq-term, Operator: and
    true: unblocked
    false: blocked
    condition:
        Terms:
            - Right: {Value: unblocked}
              Left:  {Value: '%action-N%'}
              Operator: eq
        Operator: and
  actions:
    - # ...
```

---

## Action-level — FULL field inventory

| Field | Type | Required | Example / value |
|---|---|---|---|
| `name` | string | yes | `Display the Current User Name Using "whoami" Command` |
| `description` | string | yes | `In this action, an attacker is trying to determine which user rights they have access to.` (inline, NOT ` | `-`) |
| `tactic` | string | yes | `TA0007`, `TA0006`, `TA0009` |
| `technique` | string | yes | `T1033`, `T1057`, `T1217`, `T1555` |
| `sub_technique` | string | optional | `T1497.001` |
| `affected_os` | list | yes | `[- macOS]` |
| `affected_platforms` | list[object] | yes | the 5-entry macOS block above |
| `is_atomic` | bool | yes | `true` |
| `ukc_phase` | string | yes | `Discovery`, `Credential Access`, `Collection`, `Execution` |
| `category` | string | yes | `Attack Scenario` |
| `is_applicable_to_all_platforms` | bool | optional | `true` (omitted on actions with `remote_files`) |
| `is_privileged` | bool | optional | `true` on credential-access actions |
| `result_condition` | object | yes | `%process-N%` references, Operator `and` |
| `play_processes` | list[step] | yes | see below |
| `rewind_processes` | list[step] | optional | `{arguments: rm -rf ...}` only |
| `keyword_queries` | list[string] | yes | one boolean expression |

**Notably absent** (vs. Linux/Windows Endpoint):

- No `title` field (unlike other Endpoint modules)
- No `is_privileged` unless the action explicitly needs elevation

---

## `play_processes` step shapes — three flavours

macOS actions don't always wrap in a shell — they often play binaries directly:

**1. Path-only (no arguments, no remote_files):**

```yaml
play_processes:
    - path: /usr/bin/whoami
```

**2. Path + arguments (no remote_files):**

```yaml
play_processes:
    - path: /bin/ps
      arguments: aux
```

**3. Path + arguments + remote_files + success_conditions (download-and-execute):**

```yaml
play_processes:
    - path: /tmp/hack-browser-data
      arguments: -b all
      remote_files:
        - file: files/aGFjay1icm93c2VyLWRhdGFfX181YzNlZTFlYi03YTI5LTRiOTMtYjdkZS1mYjQ4ODZjMTMwNTE=
          path: /tmp/hack-browser-data
          is_executable: true
          is_downloaded: true
      success_conditions:
        - output: bookmark.csv success
```

**4. Arguments-only (no path):**

```yaml
play_processes:
    - arguments: sysctl -a | grep machdep.cpu
```

(Yes, `arguments` can appear without `path` — Picus then invokes through `$SHELL`.)

**Common macOS binary paths seen:**

- `/usr/bin/whoami`, `/usr/bin/sw_vers`, `/bin/ps`, `/bin/find`, `/usr/bin/osascript` (AppleScript runner), `security` (Keychain), `sysctl`, `defaults`

**Common macOS-specific arguments:**

- `security 2>&1 &gt /dev/null find-generic-password -ga 'Chrome' | awk '{print $2}' | tr -d '"' &gt; /tmp/key.txt` (extract Chrome keychain entry)
- `osascript -e 'tell application "System Events" to keystroke "..."'` (UI scripting — not seen in canonical Realst but typical for macOS Endpoint)

---

## `rewind_processes` substructure

macOS rewind entries carry ONLY `arguments` (no `path`, no `remote_files`):

```yaml
rewind_processes:
    - arguments: rm -rf /tmp/hack-browser-data
    - arguments: rm -rf /tmp/results
```

The consistent idea: remove staged binaries from `/tmp/`. No `kill -9 <pid>` patterns — macOS rewinds use simpler `rm -rf` cleanup.

---

## `keyword_queries` canonical template

```yaml
keyword_queries:
    - ( (<DETECT-OR> ) AND NOT (("rm" AND " -rf") OR "com.apple.quarantine" OR "PICUS_REWIND") )
```

**macOS-specific noise exclusion:** `com.apple.quarantine` (Gatekeeper quarantine attribute) + `PICUS_REWIND` (Picus rewind marker).

**`DETECT-OR`** is OR'd over:

1. **Tool/process-name token** (e.g. `("/usr/bin/whoami ")`)
2. **Basename + UUID tag:** `("hack-browser-data" OR "hack-browser-data___<uuid>")`
3. **Hash triple:** `("sha256" OR "sha1" OR "md5")`
4. **Command-line fingerprint:** `("token1" AND "token2")` — AND-joined fragments

Concrete examples:

```yaml
# Simple binary invocation
keyword_queries:
    - ("/usr/bin/whoami ")

# ps aux
keyword_queries:
    - ("/bin/ps" AND "aux")

# HackBrowserData with hashes + UUID tag
keyword_queries:
    - (("hack-browser-data" OR "8646b6c008282fb5172d07b90d12485f172ffadc" OR "6ef29251542fb11f35ee574c63261c04c2c55b1374542a76" OR "a2d4f5633733c7b856922413616db377") AND NOT (("rm" AND " -rf") OR "com.apple.quarantine" OR "PICUS_REWIND"))
```

---

## Real worked example (full action)

```yaml
- name: Discover Browser Bookmarks via HackBrowserData Tool
  description: In this action, an attacker is trying to find saved bookmarks of installed browsers on the target machine via the HackBrowserData tool.
  tactic: TA0007
  technique: T1217
  affected_os:
    - macOS
  affected_platforms:
    - name: MacOS 26 Tahoe
      architecture: 64-bit
    - name: MacOS 14 Sonoma
      architecture: 64-bit
    - name: MacOS 13 Ventura
      architecture: 64-bit
    - name: MacOS 15 Sequoia
      architecture: 64-bit
    - name: MacOS 12 Monterey
      architecture: 64-bit
  is_atomic: true
  ukc_phase: Discovery
  category: Attack Scenario
  result_condition:
    true: unblocked
    false: blocked
    condition:
        Terms:
            - Right:
                Value: unblocked
              Left:
                Value: '%process-1%'
              Operator: eq
        Operator: and
  play_processes:
    - path: /tmp/hack-browser-data
      arguments: -b all
      remote_files:
        - file: files/aGFjay1icm93c2VyLWRhdGFfX181YzNlZTFlYi03YTI5LTRiOTMtYjdkZS1mYjQ4ODZjMTMwNTE=
          path: /tmp/hack-browser-data
          is_executable: true
          is_downloaded: true
      success_conditions:
        - output: bookmark.csv success
  rewind_processes:
    - arguments: rm -rf /tmp/hack-browser-data
    - arguments: rm -rf /tmp/results
  keyword_queries:
    - (("hack-browser-data" OR "8646b6c008282fb5172d07b90d12485f172ffadc" OR "6ef29251542fb11f35ee574c63261c04c2c55b1374542a76" OR "a2d4f5633733c7b856922413616db377") AND NOT (("rm" AND " -rf") OR "com.apple.quarantine" OR "PICUS_REWIND"))
```

---

## Difference vs. Linux Endpoint Scenario

| Aspect | macOS Endpoint | Linux Endpoint |
|---|---|---|
| `module` value | `macOS Endpoint Scenario` | `Linux Endpoint Scenario` |
| `affected_os` | `[- macOS]` (mixed case) | `[- Linux]` |
| `affected_platforms` block | 5 macOS releases, block style | 16 Linux distros, inline flow style |
| `title` action field | **absent** | present (snake_case) |
| `is_applicable_to_all_platforms` | present on simpler actions | varies |
| `description` style | inline string (NOT ` | `-`) | ` | `-` block scalar |
| `play_processes` shell pattern | plays binaries directly (`/usr/bin/whoami`, `/bin/ps`) — no `/bin/sh` wrapper | `path: /bin/sh` + `arguments: -c "..."` shell wrapper |
| `play_processes[].timeout` | absent | `timeout: 15` |
| `keyword_queries` noise exclusion | `("rm" AND " -rf") OR "com.apple.quarantine" OR "PICUS_REWIND"` | `"pkill" OR "killall" OR ("rm" AND "-rf")` |
| `keyword_queries` shell token | none (no shell wrapper) | required: `"bash" OR "sh" OR "dash"` |
| `rewind_processes` style | `arguments: rm -rf <path>` only | may include `history -c; unset HISTFILE` + `rm -rf` |
| `is_privileged` | optional, true on credential-access | often true on credential-access |

---

## Authoring checklist

- [ ] `module: macOS Endpoint Scenario` (lowercase `m` in `macOS`)
- [ ] `affected_os: [- macOS]`
- [ ] Every action carries the 5-entry macOS `affected_platforms` block
- [ ] No `title` field on actions
- [ ] `category: Attack Scenario`, `is_atomic: true`
- [ ] `play_processes` plays binaries directly (no `/bin/sh` shell wrapper unless needed)
- [ ] `keyword_queries` ends with `AND NOT (("rm" AND " -rf") OR "com.apple.quarantine" OR "PICUS_REWIND")`
- [ ] `description` is inline (single-line string), NOT ` | `-block
- [ ] Result condition uses `Operator: and` (not `or` — that's K8s)
- [ ] ZIP password: `picus` (AES-256 via `7z -mem=AES256 -tzip`)
</content>
</invoke>