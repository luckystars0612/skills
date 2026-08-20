#!/usr/bin/env python3
"""build_threat.py — assemble a Picus threat.yaml from ActionSpec objects.

This is the *core* of the skill. It owns:

    - the `_TARGET_TABLE` — the Linux target file → MITRE / UKC / output map
      (mirror of `references/mappings/linux-targets.md`).
    - the `LINUX_PLATFORMS` — the 16-distro block (mirror of
      `references/mappings/linux-platforms.md`).
    - the `KEYWORD_QUERY_TEMPLATE` — the canonical keyword_queries pattern.
    - the `build_actions` / `build_objectives` / `build_campaign` emitters.

The parsers (`parse_spl.py`, `parse_sigma.py`, `parse_goal.py`) produce a list
of `ActionSpec` objects; this module consumes them and writes the final
`threat.yaml`.

CLI usage:

    python build_threat.py \\
        --title "Linux Sensitive File Access via Shell" \\
        --description "Detects shell access to /etc/shadow, ..." \\
        --severity High \\
        --actions-json /tmp/actions.json \\
        --output /tmp/campaign/threat.yaml

The `--actions-json` file is a JSON list of dicts with the ActionSpec fields
(see `actionspec.py`).
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Canonical 16-distro Linux block (mirror of references/mappings/linux-platforms.md)
# ---------------------------------------------------------------------------
LINUX_PLATFORMS: list[dict[str, str]] = [
    {"name": "Red Hat Enterprise Linux 10", "architecture": "64-bit"},
    {"name": "Rocky Linux 9",                "architecture": "64-bit"},
    {"name": "Ubuntu 22.04",                 "architecture": "64-bit"},
    {"name": "CentOS 8",                     "architecture": "64-bit"},
    {"name": "Red Hat Enterprise Linux 8",   "architecture": "64-bit"},
    {"name": "Alpine 3.22",                  "architecture": "64-bit"},
    {"name": "SUSE 15.7",                    "architecture": "64-bit"},
    {"name": "Alpine 3.21",                  "architecture": "64-bit"},
    {"name": "SUSE 15.6",                    "architecture": "64-bit"},
    {"name": "CentOS 9",                     "architecture": "64-bit"},
    {"name": "Debian 12",                    "architecture": "64-bit"},
    {"name": "Ubuntu 24.04",                 "architecture": "64-bit"},
    {"name": "Red Hat Enterprise Linux 9",   "architecture": "64-bit"},
    {"name": "Debian 11",                    "architecture": "64-bit"},
    {"name": "Debian 10",                    "architecture": "64-bit"},
    {"name": "Ubuntu 20.04",                 "architecture": "64-bit"},
]

# ---------------------------------------------------------------------------
# Linux target file → MITRE / UKC / output map (mirror of references/mappings/linux-targets.md)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class TargetRow:
    target_regex: str
    canonical_path: str
    display_name: str
    tactic: str
    technique: str
    sub_technique: str
    ukc_phase: str
    is_privileged: bool
    expected_output: str


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

_FALLBACK_ROW = TargetRow(
    "<unknown>", "<unknown>", "Read target file",
    "TA0007", "T1083", "", "Discovery", False, " ",
)


def lookup_target(token: str) -> TargetRow:
    """Return the best-matching TargetRow for a token from SPL/Sigma/goal.

    Lookup order:
    1. Exact match (token or stripped form).
    2. Substring match: token contains any target_regex (longest wins).
    3. Prefix match EITHER direction — the token is a prefix of any
       target_regex (e.g. `/proc/net` matches `/proc/net/tcp` and
       `/proc/net/`), OR a target_regex is a prefix of the token.
    4. Last-ditch: backslash-stripped substring.
    5. Fallback.
    """
    if not token:
        return _FALLBACK_ROW
    stripped = token.strip().lstrip("/")
    # Exact matches first.
    for row in _TARGET_TABLE:
        if row.target_regex == token or row.target_regex == stripped:
            return row
    # Substring matches — longest first.
    candidates = sorted(
        [r for r in _TARGET_TABLE if r.target_regex in token or r.target_regex in stripped],
        key=lambda r: -len(r.target_regex),
    )
    if candidates:
        return candidates[0]
    # Bidirectional prefix match — the token is a prefix of any
    # target_regex, OR a target_regex is a prefix of the token.
    # Prefer the SHORTEST match in this round, because a shorter
    # target_regex like `/proc/net/` is more general than a longer one
    # like `/proc/net/tcp6` and the user almost certainly means the
    # directory enumeration when they pass a bare prefix.
    candidates = sorted(
        [r for r in _TARGET_TABLE
         if token.startswith(r.target_regex) or stripped.startswith(r.target_regex)
         or r.target_regex.startswith(token) or r.target_regex.startswith(stripped)],
        key=lambda r: len(r.target_regex),
    )
    if candidates:
        return candidates[0]
    # Last-ditch: backslash-stripped substring, e.g. ".bash_history" matches "bash_history".
    for row in _TARGET_TABLE:
        if row.target_regex.replace("\\", "") in token:
            return row
    return _FALLBACK_ROW


# ---------------------------------------------------------------------------
# ActionSpec — what the parsers produce.
# ---------------------------------------------------------------------------
@dataclass
class ActionSpec:
    name: str                # snake_case; e.g. "read_etc_shadow"
    title: str               # "Read /etc/shadow via Shell"
    description: str         # 1-2 sentence explanation
    shell_path: str          # "/bin/bash"
    shell_flag: str          # "-c"
    target_path: str         # resolved path; e.g. "/etc/shadow"
    target_regex: str        # the SPL/Sigma regex (for keyword_queries AND NOT clause)
    timeout: int = 15
    # Enrichment (filled by enrich()):
    tactic: str = ""
    technique: str = ""
    sub_technique: str = ""
    ukc_phase: str = ""
    is_privileged: bool = False
    expected_output: str = ""
    # Dropper (filled by build_dropper.py):
    dropper_name: str = ""
    dropper_sha256: str = ""
    dropper_sha1: str = ""
    dropper_md5: str = ""
    # Binary dictionary for the keyword_queries AND clause — populated from the
    # rule's `a0=...` (SPL), `Image|endswith=...` (Sigma), or detected shell
    # (plain-text goal). Defaults to canonical Linux shells when unknown.
    binaries: tuple[str, ...] = ("bash", "sh", "dash")


def enrich(spec: ActionSpec) -> ActionSpec:
    """Fill tactic/technique/ukc/etc. from the target table."""
    row = lookup_target(spec.target_regex or spec.target_path)
    spec.tactic = row.tactic
    spec.technique = row.technique
    spec.sub_technique = row.sub_technique
    spec.ukc_phase = row.ukc_phase
    spec.is_privileged = row.is_privileged
    spec.expected_output = row.expected_output
    if not spec.target_path:
        spec.target_path = row.canonical_path
    return spec


# ---------------------------------------------------------------------------
# YAML emission — done by hand to avoid PyYAML dependency.
# Indentation: 4 spaces (matches PUMAKIT / BlackMatter).
# ---------------------------------------------------------------------------
def _kv_block(d: dict[str, Any], indent: int) -> str:
    """Render a flat dict as YAML key/value lines."""
    pad = " " * indent
    out = []
    for k, v in d.items():
        if v is None or v == "":
            continue
        if isinstance(v, bool):
            out.append(f"{pad}{k}: {str(v).lower()}")
        elif isinstance(v, int):
            out.append(f"{pad}{k}: {v}")
        elif isinstance(v, str):
            # Quote if it contains special chars.
            if any(c in v for c in [":", "#", "[", "]", "{", "}", ",", "&", "*", "!", "|", ">", "'", '"', "%", "@", "`"]):
                escaped = v.replace("\\", "\\\\").replace('"', '\\"')
                out.append(f'{pad}{k}: "{escaped}"')
            else:
                out.append(f"{pad}{k}: {v}")
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, dict):
                    sub = _kv_block(item, indent + 4)
                    out.append(f"{pad}{k}:\n{sub}")
                else:
                    out.append(f"{pad}{k}: {item}")
        else:
            out.append(f"{pad}{k}: {v}")
    return "\n".join(out)


def _affected_platforms_block(indent: int) -> str:
    pad = " " * indent
    out = [f"{pad}affected_platforms:"]
    for p in LINUX_PLATFORMS:
        out.append(f"{pad}  - {{name: \"{p['name']}\", architecture: \"{p['architecture']}\"}}")
    return "\n".join(out)


def _keyword_query(spec: ActionSpec) -> str:
    """Build the canonical keyword_queries expression for an action.

    Verbatim PUMAKIT shape (5 opens / 5 closes — balanced):
        (("<sha256>" OR "<sha1>" OR "<md5>" OR "<dropper_name>" OR "<target_path>")
         AND NOT ("pkill" OR "killall" OR ("rm" AND "-rf")))

    PUMAKIT matches on the dropper name + hashes alone — no extra shell
    filter. The dropper filename is unique enough that an `AND ("bash" OR
    "sh" OR "dash")` filter is redundant. The structured template is:

        ((
            <SHA-256>
            OR <SHA-1>
            OR <MD5>
            OR <dropper_name>
            OR <target_path>
        )
        AND NOT (
            "pkill"
            OR "killall"
            OR ("rm" AND "-rf")
        ))

    Returns the bare expression (no leading `-`).
    """
    name = spec.dropper_name or spec.name
    return (
        f'(("{spec.dropper_sha256}" '
        f'OR "{spec.dropper_sha1}" '
        f'OR "{spec.dropper_md5}" '
        f'OR "{name}" '
        f'OR "{spec.target_path}") '
        f'AND NOT ("pkill" OR "killall" OR ("rm" AND "-rf")))'
    )


def _tech_id(spec: ActionSpec) -> str:
    """Render technique + optional sub_technique as `T1003.008` or `T1003`."""
    if spec.sub_technique and spec.sub_technique.startswith(spec.technique + "."):
        return spec.sub_technique
    if spec.sub_technique:
        return f"{spec.technique}.{spec.sub_technique.split('.')[-1]}"
    return spec.technique


def tech_id_only(technique: str, sub_technique: str = "") -> str:
    """Render `T1003.008` or `T1003`."""
    if sub_technique:
        if sub_technique.startswith(technique + "."):
            return sub_technique
        return f"{technique}.{sub_technique.split('.')[-1]}"
    return technique


def _action_block(spec: ActionSpec) -> str:
    """Render a single action as a YAML block.

    Indentation model (matches PUMAKIT):
        12 — `- name:` (list item under actions:)
        14 — `title:`, `description:`, ... (child fields)
        16 — `affected_os:`, `- Linux`, etc. (grandchildren)
    """
    desc = spec.description.replace("\n", " ").strip()
    sub = f"sub_technique: {spec.sub_technique}" if spec.sub_technique else ""
    safe_args = spec.target_path.replace('"', '\\"')
    kq = _keyword_query(spec)
    lines = [
        f"            - name: {spec.name}",
        f"              title: {spec.title}",
        f"              description: |",
        f"                {desc}",
        f"              affected_os:",
        f"                - Linux",
        _affected_platforms_block(14),
        f"              is_atomic: true",
        f"              is_privileged: {str(spec.is_privileged).lower()}",
        f"              ukc_phase: {spec.ukc_phase}",
        f"              category: Attack Scenario",
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


def _objective_block(ukc_phase: str, actions: list[ActionSpec], start_idx: int) -> tuple[str, int]:
    """Render one objective (one UKC phase) and return the YAML + next action index.

    Indentation:
        8  — `- type:` (list item under objectives:)
        10 — `result_condition:`, `actions:`
        12 — `- name:` (list item under actions:)

    Note: `%action-N%` is local to the objective, NOT global across the
    campaign. PUMAKIT's Defense Evasion objective uses %action-1%..%action-8%
    for its own 8 actions; the next objective resets to %action-1%. The
    campaign-level `result_condition` uses `%objective-N%` which IS global.
    """
    lines = [
        f"        - type: {ukc_phase}",
        f"          result_condition:",
        f"            true: unblocked",
        f"            false: blocked",
        f"            condition:",
        f"              Terms:",
    ]
    for i in range(len(actions)):
        lines.append(f"                - Right: {{Value: unblocked}}")
        lines.append(f"                  Left: {{Value: '%action-{i + 1}%'}}")
        lines.append(f"                  Operator: eq")
    lines.append(f"              Operator: and")
    lines.append(f"          actions:")
    for spec in actions:
        lines.append(_action_block(spec))
    return "\n".join(lines), start_idx + len(actions)


def _group_by_ukc(actions: list[ActionSpec]) -> list[tuple[str, list[ActionSpec]]]:
    """Group actions by ukc_phase, preserving original order within each group."""
    groups: dict[str, list[ActionSpec]] = {}
    for spec in actions:
        groups.setdefault(spec.ukc_phase, []).append(spec)
    return list(groups.items())


def build_threat_yaml(
    title: str,
    description: str,
    severity: str,
    actions: list[ActionSpec],
) -> str:
    """Assemble the full threat.yaml as a string."""
    groups = _group_by_ukc(actions)
    total_objectives = len(groups)

    # Campaign-level result_condition.
    if total_objectives == 1:
        campaign_rc = [
            "    result_condition:",
            "        true: unblocked",
            "        false: blocked",
            "        condition:",
            "            Right:",
            "                Value: unblocked",
            "            Left:",
            "                Value: '%objective-1%'",
            "            Operator: eq",
        ]
    else:
        campaign_rc = [
            "    result_condition:",
            "        true: unblocked",
            "        false: blocked",
            "        condition:",
            "            Terms:",
        ]
        for i in range(total_objectives):
            campaign_rc.append(f"                - Right: {{Value: unblocked}}")
            campaign_rc.append(f"                  Left: {{Value: '%objective-{i + 1}%'}}")
            campaign_rc.append(f"                  Operator: eq")
        campaign_rc.append("            Operator: and")

    # Objectives.
    idx = 0
    obj_blocks: list[str] = []
    for ukc_phase, group in groups:
        block, idx = _objective_block(ukc_phase, group, idx)
        obj_blocks.append(block)

    # Compose the file.
    safe_desc = description.replace("\n", " ")
    parts = [
        "campaign:",
        f"    name: {title}",
        f"    description: |-",
        f"        {safe_desc}",
        f"    module: Linux Endpoint Scenario",
        f"    severity: {severity}",
        f"    affected_os:",
        f"        - Linux",
    ]
    parts.extend(campaign_rc)
    parts.append("    objectives:")
    parts.extend(obj_blocks)
    return "\n".join(parts) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _load_actions(path: Path) -> list[ActionSpec]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for item in raw:
        spec = ActionSpec(
            name=item["name"],
            title=item["title"],
            description=item["description"],
            shell_path=item["shell_path"],
            shell_flag=item["shell_flag"],
            target_path=item["target_path"],
            target_regex=item["target_regex"],
            timeout=item.get("timeout", 15),
        )
        # Optional dropper fields:
        spec.dropper_name = item.get("dropper_name", "")
        spec.dropper_sha256 = item.get("dropper_sha256", "")
        spec.dropper_sha1 = item.get("dropper_sha1", "")
        spec.dropper_md5 = item.get("dropper_md5", "")
        # Binary dictionary for keyword_queries (sourced from input rule):
        bins = item.get("binaries")
        if bins:
            spec.binaries = tuple(bins)
        out.append(enrich(spec))
    return out


def main() -> None:
    p = argparse.ArgumentParser(description="Build a Picus threat.yaml from action specs.")
    p.add_argument("--title", required=True)
    p.add_argument("--description", required=True)
    p.add_argument("--severity", default="High", choices=["High", "Medium", "Low"])
    p.add_argument("--actions-json", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()

    actions = _load_actions(args.actions_json)
    yaml_text = build_threat_yaml(args.title, args.description, args.severity, actions)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(yaml_text, encoding="utf-8")
    print(f"wrote {args.output} ({len(actions)} actions)", file=sys.stderr)


if __name__ == "__main__":
    main()
