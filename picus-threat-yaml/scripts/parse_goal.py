#!/usr/bin/env python3
"""parse_goal.py — Extract ActionSpec list from a plain-text goal.

Module-aware: pass `--module windows` for Windows goals. The default
`--module linux` keeps the historical behaviour.

Usage:
    python parse_goal.py "<goal text>" [--module linux|windows] > actions.json
    python parse_goal.py goal.txt [--module windows] > actions.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from build_threat import ActionSpec, tech_id_only  # noqa: E402
from parse_spl import (
    LINUX_SHELL_BINARY_MAP, WINDOWS_SHELL_BINARY_MAP, _slug_for,
)  # noqa: E402
from profiles import get_profile  # noqa: E402


def _detect_shell(text: str, module: str) -> str:
    """Return the first shell token mentioned, or a module-appropriate default."""
    lower = text.lower()
    binary_map = WINDOWS_SHELL_BINARY_MAP if module == "windows" else LINUX_SHELL_BINARY_MAP
    for name in binary_map:
        if name in lower:
            return name
    return "cmd.exe" if module == "windows" else "bash"


def _extract_targets(text: str, profile) -> list[str]:
    """Find every target token from the profile's table that appears as substring.

    Longest match wins ties.
    """
    sorted_rows = sorted(profile.target_table, key=lambda r: -len(r.target_regex))
    found: list[str] = []
    seen: set[str] = set()
    skip_ranges: list[tuple[int, int]] = []

    for row in sorted_rows:
        needle = row.target_regex.replace("\\", "")
        idx = 0
        while True:
            pos = text.find(needle, idx)
            if pos < 0:
                break
            if any(a <= pos < b for a, b in skip_ranges):
                idx = pos + 1
                continue
            if needle not in seen:
                found.append(needle)
                seen.add(needle)
                skip_ranges.append((pos, pos + len(needle)))
            idx = pos + len(needle)
    return found


def parse_goal(text: str, timeout: int = 15, module: str = "linux") -> list[ActionSpec]:
    profile = get_profile(module)
    binary_map = WINDOWS_SHELL_BINARY_MAP if module == "windows" else LINUX_SHELL_BINARY_MAP
    default_flag = "-Command" if module == "windows" else "-c"
    default_tactic = "TA0006" if module == "windows" else "TA0007"

    shell_name = _detect_shell(text, module)
    shell_path = binary_map[shell_name]
    tokens = _extract_targets(text, profile)

    if not tokens:
        return [ActionSpec(
            name="execute_target",
            title="Execute target via shell",
            description=f"Auto-generated from goal: {text.strip()}",
            shell_path=shell_path,
            shell_flag=default_flag,
            target_path="<unknown>",
            target_regex="<unknown>",
            timeout=timeout,
            sub_technique="",
            tactic=default_tactic,
            technique="T1059",
            ukc_phase="Execution",
            is_privileged=False,
            expected_output=" ",
        )]

    specs: list[ActionSpec] = []
    seen: set[str] = set()
    for tok in tokens:
        row = profile.lookup_target(tok)
        if row.canonical_path in seen:
            continue
        seen.add(row.canonical_path)
        name = _slug_for(row.display_name)
        specs.append(ActionSpec(
            name=name,
            title=row.display_name,
            description=(
                f"Simulates shell access to {row.canonical_path} for goal "
                f"'{text.strip()}'. Covers {row.tactic} "
                f"{tech_id_only(row.technique, row.sub_technique)} "
                f"({row.ukc_phase})."
            ),
            shell_path=shell_path,
            shell_flag=default_flag,
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
            play_path=row.play_path or "",
            play_arguments=row.play_arguments or "",
        ))
    return specs


def main() -> None:
    p = argparse.ArgumentParser(description="Parse a plain-text goal into ActionSpec JSON.")
    p.add_argument("input", help="Path to goal file or '-' for stdin")
    p.add_argument("--module", default="linux", choices=["linux", "windows"],
                   help="Module (default: linux).")
    p.add_argument("--timeout", type=int, default=15)
    args = p.parse_args()
    if args.input == "-":
        text = sys.stdin.read()
    else:
        text = Path(args.input).read_text(encoding="utf-8", errors="replace")
    specs = parse_goal(text, timeout=args.timeout, module=args.module)
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
        "play_path": s.play_path,
        "play_arguments": s.play_arguments,
    } for s in specs], indent=2))


if __name__ == "__main__":
    main()
