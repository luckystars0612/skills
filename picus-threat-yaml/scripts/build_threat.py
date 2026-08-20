#!/usr/bin/env python3
"""build_threat.py — assemble a Picus threat.yaml from ActionSpec objects.

This is the *dispatcher* for the auto-pipeline. The per-module logic lives
in `profiles/` — this script:

    1. Parses CLI args (with `--module linux|windows` defaulting to linux).
    2. Loads the matching `Profile` from `profiles.get_profile()`.
    3. Enriches the action specs through the profile.
    4. Calls `profile.build_threat_yaml(...)` to render the YAML.

For back-compat, this module re-exports the symbols the parsers expect:
    ActionSpec, TargetRow, lookup_target, tech_id_only, _TARGET_TABLE

These point at the **Linux** profile by default — that's the historical
behaviour. Pass `--module windows` to get the Windows profile.

CLI usage:

    python build_threat.py \\
        --module linux|windows \\
        --title "..." \\
        --description "..." \\
        --severity High \\
        --actions-json /tmp/actions.json \\
        --output /tmp/campaign/threat.yaml
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Profile package — relative to this script.
_PKG_PARENT = Path(__file__).parent
sys.path.insert(0, str(_PKG_PARENT))

from profiles import get_profile  # noqa: E402
from profiles.base import ActionSpec, Profile, TargetRow  # noqa: E402
from profiles.base import tech_id as tech_id_only  # noqa: E402
from profiles.linux import LINUX_PLATFORMS, _TARGET_TABLE  # noqa: E402


# ---------------------------------------------------------------------------
# Back-compat aliases.
# ---------------------------------------------------------------------------
# `lookup_target` historically lived in build_threat.py. Preserve the symbol
# by pointing at the Linux profile's lookup_target (the historical default).
def lookup_target(token: str) -> TargetRow:
    """Back-compat shim — defaults to the Linux profile's target table."""
    from profiles.linux import LinuxProfile
    return LinuxProfile().lookup_target(token)


# ---------------------------------------------------------------------------
# Loader for the actions JSON.
# ---------------------------------------------------------------------------
def _load_actions(path: Path, profile: Profile) -> list[ActionSpec]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    out: list[ActionSpec] = []
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
        # Dropper hashes:
        spec.dropper_name = item.get("dropper_name", "")
        spec.dropper_sha256 = item.get("dropper_sha256", "")
        spec.dropper_sha1 = item.get("dropper_sha1", "")
        spec.dropper_md5 = item.get("dropper_md5", "")
        # Binary dictionary for keyword_queries.
        bins = item.get("binaries")
        if bins:
            spec.binaries = tuple(bins)
        # Per-action overrides:
        spec.play_path = item.get("play_path", "")
        spec.play_arguments = item.get("play_arguments", "")
        out.append(profile.enrich(spec))
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    p = argparse.ArgumentParser(description="Build a Picus threat.yaml from action specs.")
    p.add_argument(
        "--module",
        default="linux",
        choices=["linux", "windows"],
        help="Module profile (default: linux — Endpoint Scenario Windows when 'windows').",
    )
    p.add_argument("--title", required=True)
    p.add_argument("--description", required=True)
    p.add_argument("--severity", default="High", choices=["High", "Medium", "Low"])
    p.add_argument("--actions-json", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()

    profile = get_profile(args.module)
    actions = _load_actions(args.actions_json, profile)

    # Dropper hashes for keyword_queries.
    hashes_by_name: dict[str, dict[str, str]] = {}
    for item in json.loads(args.actions_json.read_text(encoding="utf-8")):
        hashes_by_name[item["name"]] = {
            "sha256": item.get("dropper_sha256", ""),
            "sha1":   item.get("dropper_sha1", ""),
            "md5":    item.get("dropper_md5", ""),
        }

    yaml_text = profile.build_threat_yaml(
        args.title, args.description, args.severity, actions, hashes_by_name,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(yaml_text, encoding="utf-8")
    print(
        f"wrote {args.output} ({len(actions)} actions, module={args.module})",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
