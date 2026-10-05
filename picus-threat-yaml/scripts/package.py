#!/usr/bin/env python3
"""package.py — Create an AES-256 password-protected ZIP of a campaign folder.

Usage:
    python package.py --campaign <dir> [--output <path>.zip] [--password picus]

Defaults:
    - output:  <campaign_parent>/<campaign_name>.zip
    - password: picus

Implementation:
    Uses the system `zip` CLI so we get true AES-256 encryption (Python's
    stdlib `zipfile` only supports the legacy ZipCrypto).
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


def _zip_binary() -> str:
    exe = shutil.which("zip")
    if not exe:
        print("package.py: `zip` not found on PATH — install it (apt install zip / brew install zip).", file=sys.stderr)
        sys.exit(1)
    return exe


def package(campaign: Path, output: Path, password: str = "picus") -> Path:
    if not campaign.is_dir():
        print(f"package.py: campaign folder not found: {campaign}", file=sys.stderr)
        sys.exit(1)

    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        output.unlink()

    # Picus REJECTS ZipCrypto (`zip -P`) with "400 invalid archive" — the archive
    # must be AES-256, which only 7z produces. Include ONLY threat.yaml and files/
    # so stray working files never end up in the package.
    if not (campaign / "threat.yaml").exists():
        print(f"package.py: no threat.yaml in {campaign}", file=sys.stderr)
        sys.exit(1)
    members = [f"{campaign.name}/threat.yaml"]
    if (campaign / "files").is_dir():
        members.append(f"{campaign.name}/files")
    cmd = ["7z", "a", "-tzip", "-mem=AES256", f"-p{password}",
           str(output), *members]
    result = subprocess.run(
        cmd,
        cwd=campaign.parent,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"package.py: zip failed (rc={result.returncode}):", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(result.returncode)
    return output


def main() -> None:
    p = argparse.ArgumentParser(description="Create a password-protected ZIP of a campaign folder.")
    p.add_argument("--campaign", required=True, type=Path)
    p.add_argument("--output", type=Path, default=None)
    p.add_argument("--password", default="picus")
    args = p.parse_args()

    output = args.output or (args.campaign.parent / f"{args.campaign.name}.zip")
    zip_path = package(args.campaign, output, password=args.password)
    print(f"ZIP: {zip_path}")
    print(f"Password: {args.password}")


if __name__ == "__main__":
    main()
