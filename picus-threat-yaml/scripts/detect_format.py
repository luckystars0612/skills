#!/usr/bin/env python3
"""detect_format.py — Auto-detect SPL / Sigma / plain-text goal.

Usage:
    python detect_format.py <input-file>

Stdout: `spl` | `sigma` | `goal`
Exit code: 0 on success, 1 on empty input.

Heuristic (in order):
1. Sigma — has `title:`, `logsource:`, and `detection:` lines near the top.
2. SPL — starts with `index=`, `sourcetype=`, or `search `; or contains `match(`
   or `stats `; or starts with a Splunk pipe `|`.
3. Otherwise — plain-text goal.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


def detect(text: str) -> str:
    """Return one of: 'spl', 'sigma', 'goal'."""
    s = text.strip()
    if not s:
        return "goal"

    # Sigma — recognizable YAML front-matter lines.
    has_title = re.search(r"^\s*title\s*:", s, re.MULTILINE) is not None
    has_logsource = re.search(r"^\s*logsource\s*:", s, re.MULTILINE) is not None
    has_detection = re.search(r"^\s*detection\s*:", s, re.MULTILINE) is not None
    if has_title and has_logsource and has_detection:
        return "sigma"

    # Splunk SPL — recognizable query tokens.
    spl_starts = ("index=", "sourcetype=", "search ", "earliest=", "latest=")
    spl_contains = ("match(", " regex ", " | stats ", " | eval ", " | table ")
    if s.startswith(spl_starts) or s.startswith("|"):
        return "spl"
    for needle in spl_contains:
        if needle in s:
            return "spl"

    return "goal"


def detect_from_path(path: str) -> str:
    p = Path(path)
    if not p.exists():
        print(f"detect_format: input not found: {path}", file=sys.stderr)
        sys.exit(1)
    text = p.read_text(encoding="utf-8", errors="replace")
    fmt = detect(text)
    print(fmt)
    return fmt


def main() -> None:
    if len(sys.argv) != 2:
        print("usage: detect_format.py <input-file>", file=sys.stderr)
        sys.exit(2)
    detect_from_path(sys.argv[1])


if __name__ == "__main__":
    main()
