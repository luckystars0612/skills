#!/usr/bin/env python3
"""profiles/linux.py — Linux Endpoint Scenario profile.

Mirrors the canonical Linux shape (PUMAKIT / BlackMatter-style):

    module:           Linux Endpoint Scenario
    affected_os:      Linux
    affected_platforms: 16-distro block (RHEL/Alpine/Ubuntu/CentOS/...)
    category:         Attack Scenario
    keyword_queries:  ((sha256 OR sha1 OR md5 OR dropper OR target)
                       AND NOT (pkill OR killall OR (rm AND -rf)))
    play_processes:   {shell_path} {shell_flag} "cat '{target_path}'"

This is byte-identical to the original build_threat.py output.
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
# Static data
# ---------------------------------------------------------------------------
LINUX_PLATFORMS: list[tuple[str, str]] = [
    ("Red Hat Enterprise Linux 10", "64-bit"),
    ("Rocky Linux 9",                "64-bit"),
    ("Ubuntu 22.04",                 "64-bit"),
    ("CentOS 8",                     "64-bit"),
    ("Red Hat Enterprise Linux 8",   "64-bit"),
    ("Alpine 3.22",                  "64-bit"),
    ("SUSE 15.7",                    "64-bit"),
    ("Alpine 3.21",                  "64-bit"),
    ("SUSE 15.6",                    "64-bit"),
    ("CentOS 9",                     "64-bit"),
    ("Debian 12",                    "64-bit"),
    ("Ubuntu 24.04",                 "64-bit"),
    ("Red Hat Enterprise Linux 9",   "64-bit"),
    ("Debian 11",                    "64-bit"),
    ("Debian 10",                    "64-bit"),
    ("Ubuntu 20.04",                 "64-bit"),
]


_TARGET_TABLE: list[TargetRow] = [
    TargetRow("/etc/shadow",      "/etc/shadow",                 "Read /etc/shadow",                  "TA0006", "T1003", "T1003.008", "Credential Access",   True,  "root:"),
    TargetRow("/etc/passwd",      "/etc/passwd",                 "Read /etc/passwd",                  "TA0007", "T1083", "",          "Discovery",           False, "root:"),
    TargetRow("/etc/gshadow",     "/etc/gshadow",                "Read /etc/gshadow",                 "TA0006", "T1003", "T1003.008", "Credential Access",   True,  ":"),
    TargetRow("/etc/sudoers",     "/etc/sudoers",                "Read /etc/sudoers",                 "TA0004", "T1548", "T1548.001", "Privilege Escalation", True,  "root"),
    TargetRow("/etc/sudoers.d/",  "/etc/sudoers.d/",             "List /etc/sudoers.d",               "TA0004", "T1548", "T1548.001", "Privilege Escalation", True,  "ALL"),
    TargetRow("/proc/net/tcp",    "/proc/net/tcp",               "Read /proc/net/tcp",                "TA0007", "T1016", "",          "Discovery",           False, "sl"),
    TargetRow("/proc/net/tcp6",   "/proc/net/tcp6",              "Read /proc/net/tcp6",               "TA0007", "T1016", "",          "Discovery",           False, "sl"),
    TargetRow("/proc/net/arp",    "/proc/net/arp",               "Read /proc/net/arp",                "TA0007", "T1018", "",          "Discovery",           False, "flags"),
    TargetRow("/proc/net/",       "/proc/net/tcp",               "Enumerate /proc/net",               "TA0007", "T1016", "",          "Discovery",           False, "sl"),
    TargetRow("authorized_keys",  "$HOME/.ssh/authorized_keys",  "Read SSH authorized_keys",          "TA0003", "T1098", "T1098.004", "Persistence",         False, "ssh-"),
    TargetRow("id_rsa",           "$HOME/.ssh/id_rsa",           "Read SSH private key",              "TA0006", "T1552", "T1552.004", "Credential Access",   False, "PRIVATE KEY"),
    TargetRow("id_ed25519",       "$HOME/.ssh/id_ed25519",       "Read SSH private key",              "TA0006", "T1552", "T1552.004", "Credential Access",   False, "PRIVATE KEY"),
    TargetRow("\\.ssh/",          "$HOME/.ssh/",                 "List SSH directory",                "TA0007", "T1083", "",          "Discovery",           False, "id_"),
    TargetRow(".bash_history",    "$HOME/.bash_history",         "Read bash history",                 "TA0006", "T1552", "T1552.003", "Credential Access",   False, " "),
    TargetRow(".bashrc",          "$HOME/.bashrc",               "Read .bashrc",                      "TA0003", "T1546", "T1546.004", "Persistence",         False, "export"),
    TargetRow("/etc/crontab",     "/etc/crontab",                "Read /etc/crontab",                 "TA0003", "T1053", "T1053.003", "Persistence",         True,  "SHELL="),
    TargetRow("/var/spool/cron/", "/var/spool/cron/",            "List cron spool",                   "TA0003", "T1053", "T1053.003", "Persistence",         True,  "SHELL="),
    TargetRow("/etc/passwd-",     "/etc/passwd-",                "Read /etc/passwd-",                 "TA0006", "T1003", "T1003.008", "Credential Access",   False, "root:"),
    TargetRow("/etc/shadow-",     "/etc/shadow-",                "Read /etc/shadow-",                 "TA0006", "T1003", "T1003.008", "Credential Access",   True,  "root:"),
    TargetRow("/etc/hosts",       "/etc/hosts",                  "Read /etc/hosts",                   "TA0007", "T1016", "",          "Discovery",           False, "localhost"),
    TargetRow("/etc/issue",       "/etc/issue",                  "Read /etc/issue",                   "TA0007", "T1082", "",          "Discovery",           False, "Linux"),
    TargetRow("/etc/os-release",  "/etc/os-release",             "Read /etc/os-release",              "TA0007", "T1082", "",          "Discovery",           False, "NAME="),
]


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------
class LinuxProfile(Profile):
    name = "linux"
    module_name = "Linux Endpoint Scenario"
    os_name = "Linux"
    default_category = "Attack Scenario"
    default_binaries = ("bash", "sh", "dash")
    keyword_and_not = '("pkill" OR "killall" OR ("rm" AND "-rf"))'

    @property
    def affected_platforms(self) -> list[tuple[str, str]]:
        return LINUX_PLATFORMS

    @property
    def target_table(self) -> list[TargetRow]:
        return _TARGET_TABLE

    def lookup_target(self, token: str) -> TargetRow:
        """Best-match lookup. Order:
        1. Exact match (token or stripped form).
        2. Substring match — longest target_regex wins.
        3. Bidirectional prefix match — shortest wins.
        4. Backslash-stripped substring.
        5. Fallback.
        """
        if not token:
            return self._fallback_row()
        stripped = token.strip().lstrip("/")
        for row in self.target_table:
            if row.target_regex == token or row.target_regex == stripped:
                return row
        candidates = sorted(
            [r for r in self.target_table
             if r.target_regex in token or r.target_regex in stripped],
            key=lambda r: -len(r.target_regex),
        )
        if candidates:
            return candidates[0]
        candidates = sorted(
            [r for r in self.target_table
             if token.startswith(r.target_regex) or stripped.startswith(r.target_regex)
             or r.target_regex.startswith(token) or r.target_regex.startswith(stripped)],
            key=lambda r: len(r.target_regex),
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
        safe_args = spec.target_path.replace('"', '\\"')
        kq = self.keyword_query(spec, hashes_)
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
            f"              category: {self.default_category}",
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
            f"                - path: {spec.shell_path}",
            f"                  arguments: {spec.shell_flag} \"cat '{safe_args}'\"",
            f"                  timeout: {spec.timeout}",
            f"                  success_conditions:",
            f"                    - output: '{spec.expected_output}'",
            f"              rewind_processes:",
            f"                - arguments: history -c; unset HISTFILE",
            f"                - arguments: rm -rf /tmp/{spec.dropper_name or spec.name}",
        ])
        return "\n".join(lines)
