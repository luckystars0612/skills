#!/usr/bin/env python3
"""profiles/base.py — shared types, helpers, and the abstract Profile class.

Every module profile (Linux, Windows, macOS, ...) subclasses `Profile` and
overrides the bits that differ. The base provides:

    - ActionSpec    — what the parsers produce (one per action).
    - TargetRow     — what the profile's lookup_target() returns.
    - Profile       — abstract base with the canonical YAML renderers.
    - _kv_block / _affected_platforms_block / _keyword_query_template
                  — small shared helpers.

Profiles MUST override:
    - module_name, os_name, default_category
    - affected_platforms
    - target_table, fallback_row, lookup_target(token)
    - render_action(spec, hashes) → YAML action block

Profiles MAY override:
    - default_binaries
    - render_objective(...) — only if the objective shape differs
    - campaign_extras()      — additional campaign-level fields
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Iterable


# ---------------------------------------------------------------------------
# TargetRow — a single entry in the profile's target → MITRE table.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class TargetRow:
    """One mapping from a SPL/Sigma token to a fully-resolved threat action.

    Fields cover everything the renderer needs to build a Picus action:
        - target_regex:     the regex the rule looks for (key)
        - canonical_path:   the canonical file path / registry key / target
        - display_name:     human-readable action title
        - tactic, technique, sub_technique, ukc_phase, category:
                            MITRE + UKC mapping
        - is_privileged:    whether the action needs admin / SYSTEM
        - expected_output:  substring the action's stdout should contain
        - play_path:        executable to invoke (Linux: /bin/bash; Windows: reg.exe)
        - play_arguments:   argument template; may use {target}, {name} placeholders
        - play_is_remote / play_needs_creds: optional lateral-movement flags
    """
    target_regex: str
    canonical_path: str
    display_name: str
    tactic: str
    technique: str
    sub_technique: str
    ukc_phase: str
    is_privileged: bool
    expected_output: str
    play_path: str = ""
    play_arguments: str = ""
    category: str = ""     # per-row override; default = profile.default_category


# ---------------------------------------------------------------------------
# ActionSpec — what the parsers (parse_spl / parse_sigma / parse_goal) emit.
# Mirrors the dataclass in the original build_threat.py so existing parsers
# import without changes.
# ---------------------------------------------------------------------------
@dataclass
class ActionSpec:
    name: str
    title: str
    description: str
    shell_path: str
    shell_flag: str
    target_path: str
    target_regex: str
    timeout: int = 15
    # Enrichment (filled by Profile.enrich()):
    tactic: str = ""
    technique: str = ""
    sub_technique: str = ""
    ukc_phase: str = ""
    is_privileged: bool = False
    expected_output: str = ""
    # Dropper hashes (filled by build_dropper.py):
    dropper_name: str = ""
    dropper_sha256: str = ""
    dropper_sha1: str = ""
    dropper_md5: str = ""
    # Binary dictionary for keyword_queries — sourced from the rule's
    # a0=... / Image|endswith=... / etc. Defaults to profile.default_binaries.
    binaries: tuple[str, ...] = ()
    # Per-action overrides (used by Windows for things like {target} expansion):
    play_path: str = ""
    play_arguments: str = ""


# ---------------------------------------------------------------------------
# Abstract Profile.
# ---------------------------------------------------------------------------
class Profile(ABC):
    """Base class for all module profiles."""

    # ----- subclasses MUST override these -----
    name: str = ""
    module_name: str = ""        # "Linux Endpoint Scenario" / "Endpoint Scenario" / ...
    os_name: str = ""            # "Linux" / "Windows" / "macOS"
    default_category: str = ""   # "Attack Scenario" / ...

    # ----- subclasses MAY override these -----
    default_binaries: tuple[str, ...] = ()
    keyword_and_not: str = ""    # AND NOT ( ... ) clause appended to keyword_queries
    campaign_extras_lines: list[str] = []   # extra lines for the campaign block

    # ----- subclasses MUST override -----
    @property
    @abstractmethod
    def affected_platforms(self) -> list[tuple[str, str]]:
        """Return [(name, architecture), ...] for this module."""
        ...

    @property
    @abstractmethod
    def target_table(self) -> list[TargetRow]:
        """Return the lookup table — list of TargetRow."""
        ...

    @abstractmethod
    def lookup_target(self, token: str) -> TargetRow:
        """Resolve a SPL/Sigma token to the best-matching TargetRow."""
        ...

    @abstractmethod
    def render_action(self, spec: ActionSpec, hashes_: dict[str, str], idx_in_obj: int) -> str:
        """Render one action as a YAML block."""
        ...

    # ----- shared helpers -----
    def _fallback_row(self) -> TargetRow:
        """Default fallback row when nothing matches."""
        return TargetRow(
            target_regex="<unknown>",
            canonical_path="<unknown>",
            display_name="Execute target via shell",
            tactic="TA0002",
            technique="T1059",
            sub_technique="",
            ukc_phase="Execution",
            is_privileged=False,
            expected_output=" ",
        )

    # ----- shared pipeline -----
    def enrich(self, spec: ActionSpec) -> ActionSpec:
        """Fill tactic/technique/ukc/etc. from the target table."""
        row = self.lookup_target(spec.target_regex or spec.target_path)
        spec.tactic = row.tactic
        spec.technique = row.technique
        spec.sub_technique = row.sub_technique
        spec.ukc_phase = row.ukc_phase
        spec.is_privileged = row.is_privileged
        spec.expected_output = row.expected_output
        if not spec.target_path:
            spec.target_path = row.canonical_path
        # Pull per-row play_path / play_arguments into the spec so the
        # renderer can use them.
        if row.play_path and not spec.play_path:
            spec.play_path = row.play_path
        if row.play_arguments and not spec.play_arguments:
            spec.play_arguments = row.play_arguments
        return spec

    def render_objective(self, ukc_phase: str, actions: list[ActionSpec],
                         hashes_by_name: dict[str, dict[str, str]]) -> str:
        """Render one objective (one UKC phase).

        The result_condition references actions by `%action-N%` local to this
        objective. The campaign-level result_condition references objectives
        by `%objective-N%` global.
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
            lines.append(self.render_action(spec, hashes_by_name[spec.name], 0))
        return "\n".join(lines)

    def build_threat_yaml(
        self,
        title: str,
        description: str,
        severity: str,
        actions: list[ActionSpec],
        hashes_by_name: dict[str, dict[str, str]],
    ) -> str:
        """Assemble the full threat.yaml as a string."""
        # Group by ukc_phase.
        groups: dict[str, list[ActionSpec]] = {}
        for spec in actions:
            groups.setdefault(spec.ukc_phase, []).append(spec)
        groups_list = list(groups.items())
        total_objectives = len(groups_list)

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

        # Render objectives.
        obj_blocks: list[str] = []
        for ukc_phase, group in groups_list:
            obj_blocks.append(self.render_objective(ukc_phase, group, hashes_by_name))

        # Compose the file.
        safe_desc = description.replace("\n", " ")
        parts = [
            "campaign:",
            f"    name: {title}",
            f"    description: |-",
            f"        {safe_desc}",
            f"    module: {self.module_name}",
            f"    severity: {severity}",
            f"    affected_os:",
            f"        - {self.os_name}",
        ]
        parts.extend(self.campaign_extras_lines)
        parts.extend(campaign_rc)
        parts.append("    objectives:")
        parts.extend(obj_blocks)
        return "\n".join(parts) + "\n"

    # ----- keyword query helpers -----
    def keyword_query(self, spec: ActionSpec, hashes_: dict[str, str]) -> str:
        """Build the canonical keyword_queries expression.

        Linux default: ((sha256 OR sha1 OR md5 OR dropper_name OR target_path)
                        AND NOT (pkill OR killall OR (rm AND -rf)))

        Windows default: ((sha256 OR sha1 OR md5 OR dropper_name OR target_path)
                          AND NOT (PICUS_REWIND OR ("File created:" AND
                                                    ("Scenarios" OR "Simulation"))))
        """
        name = spec.dropper_name or spec.name
        and_not = self.keyword_and_not or '("pkill" OR "killall" OR ("rm" AND "-rf"))'
        return (
            f'(("{hashes_["sha256"]}" '
            f'OR "{hashes_["sha1"]}" '
            f'OR "{hashes_["md5"]}" '
            f'OR "{name}" '
            f'OR "{spec.target_path}") '
            f'AND NOT {and_not})'
        )


# ---------------------------------------------------------------------------
# Shared rendering helpers (used by Linux/Windows profiles).
# ---------------------------------------------------------------------------
def kv_block(d: dict[str, Any], indent: int) -> str:
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
            if any(c in v for c in [":", "#", "[", "]", "{", "}", ",", "&", "*", "!", "|", ">", "'", '"', "%", "@", "`"]):
                escaped = v.replace("\\", "\\\\").replace('"', '\\"')
                out.append(f'{pad}{k}: "{escaped}"')
            else:
                out.append(f"{pad}{k}: {v}")
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, dict):
                    sub = kv_block(item, indent + 4)
                    out.append(f"{pad}{k}:\n{sub}")
                else:
                    out.append(f"{pad}{k}: {item}")
        else:
            out.append(f"{pad}{k}: {v}")
    return "\n".join(out)


def affected_platforms_block(platforms: Iterable[tuple[str, str]], indent: int) -> str:
    """Render `affected_platforms:` as a YAML block."""
    pad = " " * indent
    out = [f"{pad}affected_platforms:"]
    for name, arch in platforms:
        out.append(f'{pad}  - {{name: "{name}", architecture: "{arch}"}}')
    return "\n".join(out)


def tech_id(technique: str, sub_technique: str = "") -> str:
    """Render `T1003.008` or `T1003`."""
    if sub_technique:
        if sub_technique.startswith(technique + "."):
            return sub_technique
        return f"{technique}.{sub_technique.split('.')[-1]}"
    return technique
