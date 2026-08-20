#!/usr/bin/env python3
"""profiles/__init__.py — module profile registry.

A profile encapsulates everything that differs between Picus modules:
affected_platforms, target → MITRE/UKC/output table, action renderer,
keyword_queries AND-NOT clause, default shell/binary.

Profiles let `build_threat.py` and `parse_spl.py` dispatch by `--module`
flag without the per-module code being hardcoded in either script.

Usage:

    from profiles import get_profile
    profile = get_profile("linux")    # or "windows"
    yaml_text = profile.build_threat_yaml(title, description, severity, actions)
"""

from __future__ import annotations

import sys
from pathlib import Path

# Make sure the package can find its siblings when loaded as a script.
_PKG = Path(__file__).parent
if str(_PKG.parent) not in sys.path:
    sys.path.insert(0, str(_PKG.parent))
if str(_PKG) not in sys.path:
    sys.path.insert(0, str(_PKG))


def get_profile(name: str) -> "Profile":  # noqa: F821 — forward ref
    """Return the profile for the given module name.

    Accepted names:
      - "linux"          → Linux Endpoint Scenario
      - "windows"        → Endpoint Scenario (Windows)
      - "linux endpoint" → alias for "linux"
      - "endpoint"       → alias for "windows"
      - "macos"          → macOS Endpoint Scenario (TODO)
      - "kubernetes"     → Kubernetes Endpoint Scenario (TODO)

    Unknown names raise ValueError.
    """
    n = name.strip().lower()
    if n in ("linux", "linux endpoint scenario", "linux endpoint"):
        from .linux import LinuxProfile
        return LinuxProfile()
    if n in ("windows", "endpoint scenario", "endpoint", "win"):
        from .windows import WindowsProfile
        return WindowsProfile()
    raise ValueError(
        f"unknown module profile: {name!r}. "
        "Supported: linux, windows. (macOS / Kubernetes coming.)"
    )


__all__ = ["get_profile"]
