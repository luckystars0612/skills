# Picus house style — patterns read off the predefined library

Everything here is measured against the vendor's own threats on the on-prem platform
(`10.100.59.173`), not inferred from docs. Re-derive it any time with the recipe in §1.

Sample: **1,909 predefined Endpoint-family actions** (every action of every predefined threat in
attack modules 2 / 6 / 7 / 10), read 2026-10-27.

---

## 1. Read ground truth from the platform, never guess

The public API exposes the vendor's own action definitions. This is the single most useful habit
in this skill: before writing a field, look at how Picus writes it.

```bash
# the whole action, including the real path/arguments Picus uses
GET /v1/threat-library/actions/{ActionId}        ->  .module_based_details.processes[]
                                                     .frameworks.mitre / .frameworks.ukc
# bulk, up to ~50 ids per call
GET /v1/threat-library/actions?action_ids=1,2,3  ->  .actions[]
# pick sample ids from the threats of one module
GET /v1/threat-library/threats?is_predefined=true&attack_module_ids=2&limit=100
                                                 ->  .threats[].flows[].actions[].id
# a threat's full YAML (plain YAML when it carries no files; AES zip when it does)
GET /v1/threat-library/threats/{ThreatId}/export
```

Attack module ids: `1` File Download, `2` Endpoint Scenario (Windows), `3` Web Application,
`4` Email, `5` Data Exfiltration, `6` Linux Endpoint Scenario, `7` macOS Endpoint Scenario,
`9` URL Filtering, `10` Kubernetes Endpoint Scenario.

`limit` is capped at **100** on the threat/action list endpoints (`limit=200` -> HTTP 422).

---

## 2. `play_processes[].path` — OS-specific, and silent when wrong

| Module | Picus writes | Share |
|---|---|---|
| `Endpoint Scenario` (Windows) | bare exe name — `reg.exe`, `cmd.exe`, `schtasks.exe` | 1958/1976 = **99.1%** |
| `Linux Endpoint Scenario` | **no `path` key at all**, command in `arguments` | 604/622 = **97%** |
| `macOS Endpoint Scenario` | same | 292/301 = **97%** |
| `Kubernetes Endpoint Scenario` | same | 251/267 = **94%** |

The API reports a stored empty path as `" "`; in authored YAML the key is simply absent. Picus's
own exported Unix threats confirm it — the bundled Kubernetes C2 plan has 68 `- arguments:`-only
processes against 1 with a `path`, the macOS Realst campaign 8 against 3, and neither contains a
literal `path: ' '`. `path: ' '` is accepted and normalises to the same thing.

The remaining few percent are absolute paths, used only for a single bare binary with no shell
syntax (`/bin/ps aux`, `C:\Windows\System32\mmc.exe WF.msc`). Don't copy that; it is the
exception, and on an older Windows agent it breaks (§6).

### `arguments` shell semantics differ

- **Windows: no shell.** Sysmon shows `Picus.Simulator.exe` spawning the target binary directly,
  so `&`, `|`, `>`, `&&` and `%VAR%` expansion do **not** work in `arguments`. Anything needing
  them goes through an interpreter: `path: cmd.exe` + `arguments: /c …`, or
  `path: powershell.exe` + `arguments: -NoProfile -Command "…"`.
- **Unix family: shell.** With no `path`, the agent evaluates `arguments` through a shell —
  Picus's own actions depend on it, e.g.
  `arguments: LFILE=/etc/shadow; awk '//' "$LFILE"` and
  `arguments: for f in $(find / -type f -path '*/etc/passwd' …); do … done`.

### A dropped payload never goes in `path` — on Windows

Picus delivers with `remote_files` and executes through an interpreter, referring to the file by
its destination. On Unix the rule is softer: Picus does sometimes name a dropped file directly
in `path` (`- path: /tmp/hack-browser-data`, Realst campaign), but invoking it from `arguments`
is more common.

```yaml
# Windows
- path: cmd.exe
  arguments: /c "%TMP%\tool.exe" -n MsMpEng.exe -k
  remote_files:
    - file: files/<base64 blob>
      path: '%TMP%\tool.exe'
      is_executable: true
      is_downloaded: true

# Linux / macOS / Kubernetes — no `path` key
- arguments: '"$WORKDIR"/tool.elf --flag'
  remote_files:
    - file: files/<base64 blob>
      path: tool.elf
      is_executable: true
      is_downloaded: true
```

Platform-injected variables: **`%TMP%`** (Windows), **`"$WORKDIR"`** (Unix family, always
quoted), and **`$remotefile<digits>`** / **`%remotefile-<digits>%`** — a URL placeholder Picus
injects for downloader-style `T1105` actions.

---

## 3. MITRE is Picus's own catalog, not ATT&CK

Tactic ids are already documented in `accepted-values.md` (`TA0005` = "Stealth",
`TA0112` = "Defense Impairment" — neither is a UKC phase). The part that bites:

**Picus deleted MITRE's `T1562` (Impair Defenses) family** and promoted its sub-techniques to
top-level techniques under `TA0112`:

| MITRE ATT&CK | Picus |
|---|---|
| `T1562` Impair Defenses | *(does not exist)* |
| `T1562.001` Disable or Modify Tools | `T1685` |
| `T1562.002` Disable Windows Event Logging | `T1685.001` |
| `T1070.001` Clear Windows Event Logs | `T1685.005` |
| `T1562.004` Disable or Modify System Firewall | `T1686` (Windows host: `T1686.003`) |
| `T1562.009` Safe Mode Boot | `T1688` |
| `T1562.010` Downgrade Attack | `T1689` |

Techniques valid under `TA0112`: `T1112`, `T1222`, `T1553`, `T1685`, `T1686`, `T1688`, `T1689`.
Other Picus-only ids: `T1680`, `T1673`, `T1652`, `T1653`, `T1654`.

Sending `T1562` fails the import with `400 "'T1562' is not valid"` — and it refuses the **whole
pack**, not just that action. Pick the technique by looking up a predefined action that does the
same thing: "Disable Windows Defender via Backstab Tool" (action 10662) is `TA0112` / `T1685`.

Also check the tactic→technique pairing: `T1112` is real but Picus files it under `TA0112`, not
`TA0005`. `validate_threat.py` warns on pairings the predefined library never uses.

---

## 4. Import validation is strict and refuses the whole pack

| Field | Limit | Behaviour |
|---|---|---|
| `campaign.comment`, action `comment` | **255 chars** | `400 exceeds max length (458 > 255)` |
| `campaign.name` | 255 chars | — |
| `technique` / `sub_technique` | must be in Picus's catalog | `400 '<id>' is not valid` |

Older imports **silently coerced** instead of refusing: a threat imported 2026-10-22 kept
`technique: T1562` in the local YAML but ended up stored as `T1112`, and its 458-char `comment`
was truncated to `…formatted exactly as 0 [...]`. So **a local YAML is not evidence of what is on
the platform** — diff it against `/export` before trusting it.

---

## 5. Re-import is additive; you rarely need to delete

`POST /v1/threat-library/threats/import` always creates a **new** threat with new action ids; a
name collision just gets a ` (1)` suffix. So fixing a broken threat means fix YAML → import →
run, leaving the old one and its run history intact. Deleting is irreversible through the API and
takes the run history with it.

---

## 6. The failure class to recognise: silent no-op

A malformed `path` does not fail the import and does not fail the run. The symptom set:

```
run:    status COMPLETED, completion_ratio 0
threat: prevention "not tested"
action: module_based_results.process_results[].command == " "   <-- the tell
                                           .log_content == ""
host:   no child process under Picus.Simulator.exe in Sysmon
```

The platform renders the command as `path + " " + arguments`, so a lone space means the agent got
**both fields empty**.

Verified A/B, same action, same agent (`SimulationAgent04`, Windows agent **3.0.2.0**),
7 minutes apart:

| `path` written | reported `command` | spawned | output |
|---|---|---|---|
| `C:\Windows\System32\reg.exe` | `" "` | nothing | nothing |
| `' '` (the Unix form) | `" cmd.exe /c reg add …"` | nothing | nothing |
| `reg.exe` | `"reg.exe add …"` | EID1 + EID13 | `The operation completed successfully.` |

**Two traps:**

1. **`rewind_processes` still runs with an absolute path.** Rewind is executed by
   `Picus.Simulation.AgentService.exe` as SYSTEM; play is executed by `Picus.Simulator.exe` as the
   execution user. So the cleanup is visible in Sysmon and the attack is not — which reads exactly
   like an EDR prevention and sends you hunting the wrong thing.
2. Picus's own library has 18 absolute Windows paths (0.9%), so absolute is not universally
   rejected. The mechanism is not established — it may be agent-version or binary dependent. The
   bare name is the house style and is known to work.

**Always close the loop after import:** run it once and read
`GET /v1/simulations/{simId}/run/{runId}/threats/{threatId}/actions/{actionId}`
→ `module_based_results.process_results[].command` and `.log_content`. Take `runId` from
`run/latest` — it differs from `simId`. A non-empty `log_content` is the only proof the action
actually did something.

---

## 7. Checklist before shipping a custom threat

1. `python3 scripts/validate_threat.py <dir-or-yaml>` → 0 errors.
2. Windows endpoint: every `play_processes[].path` a bare exe name; shell syntax wrapped in
   `cmd.exe /c` / `powershell.exe -Command`.
3. Unix endpoint: `play_processes` entries carry **no `path` key** (or `' '`); command in `arguments`.
4. Dropped files referenced from `arguments` via `%TMP%` / `"$WORKDIR"`, never in `path`.
5. `technique` / `sub_technique` copied from a predefined action doing the same thing.
6. All `comment` fields ≤ 255 chars.
7. Import → create simulation → run → confirm `command` and `log_content` are non-empty.
8. Confirm the host-side telemetry you expect (Sysmon EID1/EID13, auditd EXECVE) actually appears.
