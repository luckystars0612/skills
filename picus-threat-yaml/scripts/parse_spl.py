#!/usr/bin/env python3
"""parse_spl.py — Extract ActionSpec list from a Splunk SPL rule.

Reads an SPL rule from a file (or stdin) and emits a JSON list of ActionSpec
dicts to stdout. The output is structured to be consumed by `build_threat.py`.

Usage:
    python parse_spl.py <input.spl> [--timeout 15] > actions.json
    cat input.spl | python parse_spl.py - > actions.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Import the shared shell-binary map and ActionSpec from build_threat.
sys.path.insert(0, str(Path(__file__).parent))
from build_threat import ActionSpec, lookup_target, tech_id_only  # noqa: E402


# Map short shell names to absolute paths.
SHELL_BINARY_MAP: dict[str, str] = {
    "bash":   "/bin/bash",
    "sh":     "/bin/sh",
    "dash":   "/bin/dash",
    "zsh":    "/bin/zsh",
    "ksh":    "/bin/ksh",
    "csh":    "/bin/csh",
    "tcsh":   "/bin/tcsh",
    "fish":   "/bin/fish",
}

# Splunk's match() / regex call:
#   match(<field>, "<pattern>")
#   regex <field>="<pattern>"
#   match(execve_command, "/etc/(shadow|passwd)")
_RE_MATCH_CALL = re.compile(
    r"""match\s*\(\s*[^,]+,\s*['"]([^'"]+)['"]\s*\)""",
    re.IGNORECASE,
)
_RE_REGEX_ASSIGN = re.compile(
    r"""regex\s+\w+\s*=\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)


def _extract_a0(spl: str) -> list[str]:
    """Extract the shell binaries from `a0="..."` clauses."""
    bins: list[str] = []
    for m in re.finditer(r"""a0\s*=\s*['"]([^'"]+)['"]""", spl, re.IGNORECASE):
        v = m.group(1).strip()
        if v and v not in bins:
            bins.append(v)
    return bins


def _extract_a1(spl: str) -> str:
    """Extract the shell flag from `a1="..."`."""
    m = re.search(r"""a1\s*=\s*['"]([^'"]+)['"]""", spl, re.IGNORECASE)
    return m.group(1).strip() if m else "-c"


def _extract_target_regex(spl: str) -> str | None:
    """Find the first match() or regex= pattern that contains a file path."""
    for pat in (_RE_MATCH_CALL, _RE_REGEX_ASSIGN):
        for m in pat.finditer(spl):
            candidate = m.group(1)
            # Heuristic: must contain a slash or a recognized file marker.
            if "/" in candidate or "." in candidate:
                return candidate
    # Fallback: take any match() group's content.
    m = _RE_MATCH_CALL.search(spl)
    if m:
        return m.group(1)
    return None


def _split_top_level_alternation(pattern: str) -> list[str]:
    """Split `a|b|c` into [a, b, c], ignoring `|` inside [...] or (...)."""
    parts: list[str] = []
    buf: list[str] = []
    bracket = 0
    paren = 0
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern):
            buf.append(c)
            buf.append(pattern[i + 1])
            i += 2
            continue
        if c == "[":
            bracket += 1
        elif c == "]" and bracket > 0:
            bracket -= 1
        elif c == "(":
            paren += 1
        elif c == ")" and paren > 0:
            paren -= 1
        elif c == "|" and bracket == 0 and paren == 0:
            parts.append("".join(buf).strip())
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    if buf:
        parts.append("".join(buf).strip())
    return [p for p in parts if p]


def _expand_paren_groups(pattern: str) -> list[str]:
    """Expand `(a|b|c)` groups into individual tokens.

    For `/etc/(shadow|passwd|gshadow)` returns ['/etc/shadow', '/etc/passwd',
    '/etc/gshadow']`.
    """
    out: list[str] = []
    top = _split_top_level_alternation(pattern)
    for token in top:
        m = re.match(r"^(.*?)\(([^)]+)\)(.*)$", token)
        if m:
            prefix, alts, suffix = m.group(1), m.group(2), m.group(3)
            for alt in _split_top_level_alternation(alts):
                inner = prefix + alt + suffix
                # Recurse one level in case there are nested groups.
                out.extend(_expand_paren_groups(inner))
        else:
            out.append(token)
    return out


def _normalize_target(token: str) -> str:
    """Strip regex anchors and leading slashes for lookup."""
    t = token.strip().lstrip("^").rstrip("$")
    # Strip leading slash only when the target is a path under root.
    return t


def _slug_for(name: str) -> str:
    """Make a snake_case action name from a target path."""
    s = re.sub(r"[^a-zA-Z0-9]+", "_", name).strip("_").lower()
    return s[:60] or "action"


def _resolve_target_path(token: str) -> str:
    """Use the linux-targets table to map a token to a canonical path."""
    row = lookup_target(token)
    return row.canonical_path


def parse_spl(text: str, timeout: int = 15) -> list[ActionSpec]:
    """Parse an SPL rule and return a list of ActionSpec objects."""
    shells = _extract_a0(text)
    if not shells:
        shells = ["bash"]
    flag = _extract_a1(text)
    pattern = _extract_target_regex(text)
    if not pattern:
        return []

    expanded = _expand_paren_groups(pattern)
    specs: list[ActionSpec] = []

    # Deduplicate resolved paths.
    seen: set[str] = set()
    for token in expanded:
        norm = _normalize_target(token)
        resolved = _resolve_target_path(norm)
        if resolved in seen:
            continue
        seen.add(resolved)

        # Use the lookup table to get the display name.
        row = lookup_target(norm)
        display = row.display_name
        name = _slug_for(display)

        specs.append(ActionSpec(
            name=name,
            title=f"{display} via Shell",
            description=(f"Simulates shell access to {resolved} in order to exercise "
                         f"{row.tactic} {tech_id_only(row.technique, row.sub_technique)} "
                         f"({row.ukc_phase})."),
            shell_path=SHELL_BINARY_MAP.get(shells[0], f"/bin/{shells[0]}"),
            shell_flag=flag,
            target_path=resolved,
            target_regex=norm,
            timeout=timeout,
            sub_technique=row.sub_technique,
            tactic=row.tactic,
            technique=row.technique,
            ukc_phase=row.ukc_phase,
            is_privileged=row.is_privileged,
            expected_output=row.expected_output,
            binaries=tuple(shells),
        ))

    return specs


def main() -> None:
    p = argparse.ArgumentParser(description="Parse a Splunk SPL rule into ActionSpec JSON.")
    p.add_argument("input", help="Path to SPL file or '-' for stdin")
    p.add_argument("--timeout", type=int, default=15)
    args = p.parse_args()

    if args.input == "-":
        text = sys.stdin.read()
    else:
        text = Path(args.input).read_text(encoding="utf-8", errors="replace")

    specs = parse_spl(text, timeout=args.timeout)
    out = []
    for s in specs:
        d = {
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
        }
        out.append(d)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
