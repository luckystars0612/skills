#!/usr/bin/env python3
"""parse_sigma.py — Extract ActionSpec list from a Sigma rule YAML.

Module-aware: pass `--module windows` for Windows Sigma rules. The default
`--module linux` keeps the historical behaviour.

Usage:
    python parse_sigma.py <rule.yml> [--module linux|windows] [--timeout 15] > actions.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from build_threat import ActionSpec, tech_id_only  # noqa: E402
from parse_spl import (
    LINUX_SHELL_BINARY_MAP, WINDOWS_SHELL_BINARY_MAP,
    _expand_paren_groups, _normalize_target, _slug_for,
)  # noqa: E402
from profiles import get_profile  # noqa: E402


# A tiny YAML loader — only good enough for Sigma rules. Requires PyYAML if
# available; otherwise falls back to a regex-based extractor.
def _load_yaml(text: str) -> dict[str, Any]:
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text) or {}
    except ImportError:
        return _regex_load(text)


def _regex_load(text: str) -> dict[str, Any]:
    """Extremely minimal Sigma loader — looks for top-level detection.selection."""
    out: dict[str, Any] = {"detection": {"selection": {}, "filter": {}, "condition": ""}}
    m = re.search(r"^\s*title\s*:\s*(.+)$", text, re.MULTILINE)
    if m:
        out["title"] = m.group(1).strip()
    sec = re.search(
        r"^\s*selection\s*:\s*\n((?:\s{4,}.+\n)+)",
        text, re.MULTILINE,
    )
    if sec:
        body = sec.group(1)
        m2 = re.search(r"CommandLine\|contains\s*:\s*\n((?:\s+-\s+.+\n)+)", body)
        if m2:
            items = re.findall(r"-\s+(.+)", m2.group(1))
            out["detection"]["selection"]["CommandLine|contains"] = [i.strip().strip("'\"") for i in items]
    return out


def _extract_targets(detection: dict[str, Any]) -> list[str]:
    """Extract target file paths / process names from the detection selection."""
    sel = detection.get("selection", {}) or {}
    targets: list[str] = []

    items = sel.get("CommandLine|contains") or sel.get("CommandLine|contains|all") or []
    if isinstance(items, str):
        items = [items]
    for item in items:
        if "/" in item or "\\" in item or "." in item:
            targets.append(item)

    for item in sel.get("CommandLine|endswith") or []:
        targets.append(item)

    for pat in sel.get("CommandLine|re") or []:
        targets.extend(_expand_paren_groups(pat))

    return targets


def _extract_shells(detection: dict[str, Any], module: str) -> list[str]:
    """Extract process binaries from Image|endswith / Image|contains etc."""
    sel = detection.get("selection", {}) or {}
    candidates: list[str] = []
    binary_map = WINDOWS_SHELL_BINARY_MAP if module == "windows" else LINUX_SHELL_BINARY_MAP
    default = "cmd.exe" if module == "windows" else "bash"
    for field in ("Image|endswith", "Image|contains", "ProcessName|endswith"):
        for v in sel.get(field) or []:
            base = Path(v).name
            if base in binary_map and base not in candidates:
                candidates.append(base)
    return candidates or [default]


def parse_sigma(text: str, timeout: int = 15, module: str = "linux") -> list[ActionSpec]:
    rule = _load_yaml(text)
    detection = rule.get("detection", {}) or {}
    profile = get_profile(module)
    targets = _extract_targets(detection)
    shells = _extract_shells(detection, module)
    binary_map = WINDOWS_SHELL_BINARY_MAP if module == "windows" else LINUX_SHELL_BINARY_MAP
    default_flag = "-Command" if module == "windows" else "-c"
    default_binaries = ("cmd.exe", "powershell.exe") if module == "windows" else ("bash", "sh", "dash")

    if not targets:
        return []

    specs: list[ActionSpec] = []
    shell = binary_map.get(shells[0], f"/usr/bin/{shells[0]}" if module == "linux" else f"C:\\Windows\\System32\\{shells[0]}")
    seen: set[str] = set()
    for tok in targets:
        norm = _normalize_target(tok)
        row = profile.lookup_target(norm)
        resolved = row.canonical_path
        if row.target_regex in seen:
            continue
        seen.add(row.target_regex)
        name = _slug_for(row.display_name)
        specs.append(ActionSpec(
            name=name,
            title=f"{row.display_name} via Shell",
            description=(
                f"Simulates shell access to {resolved} for Sigma rule "
                f"'{rule.get('title', '')}'. Covers {row.tactic} "
                f"{tech_id_only(row.technique, row.sub_technique)} "
                f"({row.ukc_phase})."
            ),
            shell_path=shell,
            shell_flag=default_flag,
            target_path=resolved,
            target_regex=norm,
            timeout=timeout,
            sub_technique=row.sub_technique,
            tactic=row.tactic,
            technique=row.technique,
            ukc_phase=row.ukc_phase,
            is_privileged=row.is_privileged,
            expected_output=row.expected_output,
            binaries=tuple(shells) if shells else default_binaries,
            play_path=row.play_path or "",
            play_arguments=row.play_arguments or "",
        ))
    return specs


def main() -> None:
    p = argparse.ArgumentParser(description="Parse a Sigma rule into ActionSpec JSON.")
    p.add_argument("input")
    p.add_argument("--module", default="linux", choices=["linux", "windows"],
                   help="Module (default: linux).")
    p.add_argument("--timeout", type=int, default=15)
    args = p.parse_args()
    text = Path(args.input).read_text(encoding="utf-8", errors="replace")
    specs = parse_sigma(text, timeout=args.timeout, module=args.module)
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
