#!/usr/bin/env python3
"""parse_goal.py — Extract ActionSpec list from a plain-text goal.

Usage:
    python parse_goal.py "<goal text>" > actions.json
    python parse_goal.py goal.txt > actions.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from build_threat import ActionSpec, _TARGET_TABLE, lookup_target, tech_id_only  # noqa: E402
from parse_spl import SHELL_BINARY_MAP, _slug_for  # noqa: E402


def _detect_shell(text: str) -> str:
    """Return the first shell token mentioned, or 'bash'."""
    lower = text.lower()
    for name in SHELL_BINARY_MAP:
        if name in lower:
            return name
    return "bash"


def _extract_targets(text: str) -> list[str]:
    """Find every target token from `_TARGET_TABLE` that appears as substring.

    Longest match wins ties.
    """
    # Build a list of (regex, row) sorted by length descending.
    sorted_rows = sorted(_TARGET_TABLE, key=lambda r: -len(r.target_regex))
    found: list[str] = []
    seen: set[str] = set()
    skip_ranges: list[tuple[int, int]] = []

    for row in sorted_rows:
        # Search for the raw token in the text.
        needle = row.target_regex.replace("\\", "")
        idx = 0
        while True:
            pos = text.find(needle, idx)
            if pos < 0:
                break
            # Check overlap with already-found ranges.
            if any(a <= pos < b for a, b in skip_ranges):
                idx = pos + 1
                continue
            if needle not in seen:
                found.append(needle)
                seen.add(needle)
                skip_ranges.append((pos, pos + len(needle)))
            idx = pos + len(needle)
    return found


def parse_goal(text: str, timeout: int = 15) -> list[ActionSpec]:
    shell_name = _detect_shell(text)
    shell_path = SHELL_BINARY_MAP[shell_name]
    tokens = _extract_targets(text)

    if not tokens:
        # Fallback: a single action with the bare goal.
        return [ActionSpec(
            name="read_target_file",
            title="Read target file via Shell",
            description=f"Auto-generated from goal: {text.strip()}",
            shell_path=shell_path,
            shell_flag="-c",
            target_path="<unknown>",
            target_regex="<unknown>",
            timeout=timeout,
            sub_technique="",
            tactic="TA0007",
            technique="T1083",
            ukc_phase="Discovery",
            is_privileged=False,
            expected_output=" ",
        )]

    specs: list[ActionSpec] = []
    resolved_seen: set[str] = set()
    for tok in tokens:
        row = lookup_target(tok)
        if row.canonical_path in resolved_seen:
            continue
        resolved_seen.add(row.canonical_path)
        name = _slug_for(row.display_name)
        specs.append(ActionSpec(
            name=name,
            title=f"{row.display_name} via Shell",
            description=(f"Simulates shell access to {row.canonical_path} for goal "
                         f"'{text.strip()}'. Covers {row.tactic} "
                         f"{tech_id_only(row.technique, row.sub_technique)} "
                         f"({row.ukc_phase})."),
            shell_path=shell_path,
            shell_flag="-c",
            target_path=row.canonical_path,
            target_regex=tok,
            timeout=timeout,
            sub_technique=row.sub_technique,
            tactic=row.tactic,
            technique=row.technique,
            ukc_phase=row.ukc_phase,
            is_privileged=row.is_privileged,
            expected_output=row.expected_output,
            binaries=(shell_name,),
        ))
    return specs


def main() -> None:
    p = argparse.ArgumentParser(description="Parse a plain-text goal into ActionSpec JSON.")
    p.add_argument("input", help="Path to goal file or '-' for stdin")
    p.add_argument("--timeout", type=int, default=15)
    args = p.parse_args()
    if args.input == "-":
        text = sys.stdin.read()
    else:
        text = Path(args.input).read_text(encoding="utf-8", errors="replace")
    specs = parse_goal(text, timeout=args.timeout)
    print(json.dumps([{
        "name": s.name,
        "title": s.title,
        "description": s.description,
        "shell_path": s.shell_path,
        "shell_flag": s.shell_flag,
        "target_path": s.target_path,
        "target_regex": s.target_regex,
        "timeout": s.timeout,
        "tactic": s.tactic,
        "technique": s.technique,
        "sub_technique": s.sub_technique,
        "ukc_phase": s.ukc_phase,
        "is_privileged": s.is_privileged,
        "expected_output": s.expected_output,
        "binaries": list(s.binaries),
    } for s in specs], indent=2))


if __name__ == "__main__":
    main()
