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

Pagination is **`offset`**, not `page` — `?limit=100&offset=200`. `limit` is capped at 100 and
`limit=500` silently returns 0 rows. `search=`, `attack_module_id=` and `is_predefined=` are
accepted but **ignored** on `/v1/threat-library/threats`; to find a threat that uses a given
action, page through with `offset` and match `flows[].actions[].id` yourself.

A predefined threat's export is an **AES zip, password `picus`** — the same password you package
with. Extract it with `7z x -p"picus"`; inside are `threat.yaml` and `files/`.

### The API and the YAML are authoritative for different things

| Authoritative source | Fields |
|---|---|
| `GET .../actions/{id}` | `module_based_details` (paths, arguments, file hashes), `frameworks.mitre`, `frameworks.ukc`, `attack_category`, `affected_os`, `keyword_queries`, `owasp`/`cwe`/`cve` |
| a threat **export** (`threat.yaml`) | everything you actually author: `ukc_phase`, `category`, `title`, `is_atomic`, `is_privileged`, `comment`, `result_condition`, `success_conditions`, `remote_files`, `rewind_processes`, `affected_platforms` |

Do not conclude a field is unused because the actions API omits it. The API returns no
`frameworks` block at all for File Download, Email, Web Application and URL Filtering, yet their
authored YAML still carries `ukc_phase` and `category` on every action.

### Module census

Probed ids 1-16 on 2026-10-27; **only these nine exist**, and the threat counts are what the
library actually holds (predefined + custom):

| id | `module:` value | threats |
|---|---|---|
| 1 | `File Download` | 3619 |
| 2 | `Endpoint Scenario` (Windows) | 267 |
| 3 | `Web Application` | 430 |
| 4 | `Email` | 3231 |
| 5 | `Data Exfiltration` | 68 |
| 6 | `Linux Endpoint Scenario` | 84 |
| 7 | `macOS Endpoint Scenario` | 44 |
| 9 | `URL Filtering` | 38 |
| 10 | `Kubernetes Endpoint Scenario` | 13 |

Ids `8` and `11`-`16` return 0 threats. **There is no Cloud Emulation attack module on this
platform** — so `module: AWS Cloud Emulation` (and the Azure/GCP variants) cannot be imported
here, and `references/modules/cloud-emulation.md` is unverified against any real threat. Cloud
scenarios in this environment are authored as `Linux Endpoint Scenario` actions that call the
cloud API (that is how `bas_fp100/05_aws_mfa_disabled` is built).

`limit` is capped at **100** on the threat/action list endpoints (`limit=200` -> HTTP 422).

---

## 2. `play_processes[].path` — OS-specific, and silent when wrong

Measured over all 3,704 processes in the 2,252 predefined Endpoint-family actions:

| Module | Picus writes | Share |
|---|---|---|
| `Endpoint Scenario` (Windows) | bare exe name — `reg.exe`, `cmd.exe`, `schtasks.exe` | 1902/2508 = **75.8%** |
| `Endpoint Scenario` (Windows) | `%TMP%\<dropped>.exe` — the payload it just dropped | 583/2508 = **23.2%** |
| `Endpoint Scenario` (Windows) | `{predefined-*}` pseudo-process (see `modules/endpoint.md`) | 441/2508 = **17.6%** of which a subset overlaps the rows above |
| `Linux Endpoint Scenario` | **no `path` key at all**, command in `arguments` | 604/628 = **96.2%** |
| `macOS Endpoint Scenario` | same | 292/301 = **97.0%** |
| `Kubernetes Endpoint Scenario` | same | 251/267 = **94.0%** |

The API reports a stored empty path as `" "`; in authored YAML the key is simply absent. Picus's
own exported Unix threats confirm it — the bundled Kubernetes C2 plan has 68 `- arguments:`-only
processes against 1 with a `path`, the macOS Realst campaign 8 against 3, and neither contains a
literal `path: ' '`. `path: ' '` is accepted and normalises to the same thing.

Absolute paths are 23/2508 on Windows and 3.5-5.2% on Unix. On Windows every one of the 23 is a
binary that is **not reachable by name** (`...\Framework64\v4.0.30319\MSBuild.exe`,
`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`) or a drop outside `%TMP%`.
Only 3 name something already on `PATH`. Never write an absolute path for a binary on `PATH`:
`C:\Windows\System32\reg.exe` measured `not tested` / `command = " "` / no output on agent
3.0.2.0, where bare `reg.exe` gave 100% and real output in the same minute (§6).

### `arguments` shell semantics differ

- **Windows: no shell.** Sysmon shows `Picus.Simulator.exe` spawning the target binary directly,
  so `&`, `|`, `>`, `&&` and `%VAR%` expansion do **not** work in `arguments`. Anything needing
  them goes through an interpreter: `path: cmd.exe` + `arguments: /c …`, or
  `path: powershell.exe` + `arguments: -NoProfile -Command "…"`.
- **Unix family: shell.** With no `path`, the agent evaluates `arguments` through a shell —
  Picus's own actions depend on it, e.g.
  `arguments: LFILE=/etc/shadow; awk '//' "$LFILE"` and
  `arguments: for f in $(find / -type f -path '*/etc/passwd' …); do … done`.

### A dropped payload goes directly in `path`

On Windows the dropped file **is** the `path`, with its `remote_files` nested in the same
process — 575 of 2508 processes. Reach for `cmd.exe /c` only when the invocation needs shell
syntax (a pipe, `&&`, a redirect, an inner quoted command). On Unix either form is used; naming
it in `arguments` is the more common.

The `files/` entry name is **base64 of `<basename>___<uuid>.<ext>`**, and the `path:` beside it
is where the agent writes the file.

```yaml
# Windows — the vendor's own form (TIDrone campaign, threat 138)
- path: '%TMP%\tool.exe'
  remote_files:
    - file: files/<base64 of tool___<uuid>.exe>
      path: '%TMP%\tool.exe'
      is_downloaded: true

# Linux / macOS / Kubernetes — no `path` key
- arguments: '"$WORKDIR"/tool.elf --flag'
  remote_files:
    - file: files/<base64 blob>
      path: tool.elf
      is_executable: true
      is_downloaded: true
```

Platform-injected variables: **`%TMP%`** (Windows, 1580 uses), **`"$WORKDIR"`** (Unix family,
617, always quoted), **`$remotefile<digits>`** / **`%remotefile-<digits>%`** — a URL placeholder
for downloader-style `T1105` actions, never valid in `path` — and, for
`category: Lateral Movement Techniques` only, the peer-host set **`%REMOTEIP%`,
`%REMOTEHOSTNAME%`, `%REMOTEDOMAIN%`, `%REMOTEUSERNAME%`, `%REMOTEPASSWORD%`**, which the
platform fills from the agent pair chosen for the simulation. `is_remote:` and `needs_creds:`
exist only in Picus's internal UI action payload, never in authored YAML — 0 occurrences in
31,356 actions and 18 exported threats. Import accepts and ignores them.

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

## 7. `keyword_queries` — one template per module, plus a mandatory OS guard

The detection keyword is what makes an action *Logged*. Measured 31,356/31,356 predefined actions
carry exactly one `Default` query. The template is module-specific:

| Module | Template (from a real action) |
|---|---|
| `File Download` | `(("<sha256>" OR "<sha1>" OR "<md5>") OR ("<md5>" AND "<ext>"))` |
| `Email` | `(("<display_id>" AND ("Attachment" OR "URL")) OR (("<sha256>" OR "<sha1>" OR "<md5>") OR ("<md5>" AND "<ext>")))` |
| `Data Exfiltration` | `(((("act_id" AND "<action_id>") OR "-<action_id>-" OR "\|<action_id>\|") OR (("<sha1>" OR "<sha256>" OR "<md5>") OR ("<display_id>" AND "<ext>"))) AND NOT ("picexfil" AND "short-url"))` |
| `Web Application` | `("page<display_id>")` — nothing else |
| `URL Filtering` | `("<hostname>")` — the bare host, e.g. `("notebooklm.google.com")` |
| `Endpoint` (all 4) | command-shape terms ANDed together, then the OS guard below |

Endpoint queries name the distinctive tokens of the command, not the whole command:

```
("schtasks" AND "/create" AND ("GoogleCrash.exe" OR "Chrome")) AND (("\schtasks.exe" AND " /create ") AND ("AppData" OR "Public" OR "C:\Windows\Temp"))
(("LFILE" AND "etc" AND "shadow") OR "awk")
```

**Most endpoint queries end with an OS-specific `AND NOT` guard** that suppresses Picus's own
cleanup and staging noise — Windows 1197/1537 (78%), Linux 284/330 (86%), Kubernetes 136/168
(81%), macOS 212/217 (98%). It is the house default rather than a hard rule; Picus omits it on
the rest. Copy it verbatim for the module you are targeting:

| Module | Guard |
|---|---|
| `Endpoint Scenario` (Windows) | `AND NOT ("PICUS_REWIND" OR ("File created:" AND ("Scenarios" OR "Simulation")))` |
| `Linux Endpoint Scenario`, `Kubernetes Endpoint Scenario` | `AND NOT ("pkill" OR "killall" OR ("rm" AND "-rf"))` |
| `macOS Endpoint Scenario` | `AND NOT (("rm" AND " -rf") OR "com.apple.quarantine" OR "PICUS_REWIND")` |

Without the guard the `rewind_processes` cleanup matches your own keyword and the action can
grade Logged on the teardown instead of the attack.

---

## 8. Checklist before shipping a custom threat

1. `python3 scripts/validate_threat.py <dir-or-yaml>` → 0 errors.
2. Windows endpoint: every `play_processes[].path` is a bare exe name, a `%TMP%\…` drop, or a
   `{predefined-*}` token — never an absolute path to something on `PATH`. Shell syntax wrapped
   in `cmd.exe /c` / `powershell.exe -Command`.
3. Unix endpoint: `play_processes` entries carry **no `path` key** (or `' '`); command in `arguments`.
4. A dropped Windows payload sits in `path` as `%TMP%\tool.exe` with its `remote_files` nested in
   the same process; on Unix run it from `arguments` via `"$WORKDIR"`.
4b. `keyword_queries` carries the OS-specific `AND NOT` guard from §7.
5. `technique` / `sub_technique` copied from a predefined action doing the same thing.
6. All `comment` fields ≤ 255 chars.
7. Import → create simulation → run → confirm `command` and `log_content` are non-empty.
8. Confirm the host-side telemetry you expect (Sysmon EID1/EID13, auditd EXECVE) actually appears.
