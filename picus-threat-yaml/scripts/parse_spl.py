#!/usr/bin/env python3
"""parse_spl.py — Extract ActionSpec list from a Splunk SPL rule.

Reads an SPL rule from a file (or stdin) and emits a JSON list of ActionSpec
dicts to stdout. The output is structured to be consumed by `build_threat.py`.

Module-aware: pass `--module windows` to parse a Windows SPL (recognises
`Image=`, `Image|endswith=`, `process_name=` fields and maps to the Windows
target table). Default `--module linux` keeps the historical behaviour.

Usage:
    python parse_spl.py <input.spl> [--module linux|windows] [--timeout 15] > actions.json
    cat input.spl | python parse_spl.py - [--module windows] > actions.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Import the shared shell-binary map and ActionSpec from build_threat.
sys.path.insert(0, str(Path(__file__).parent))
from build_threat import ActionSpec, tech_id_only  # noqa: E402

# Profiles — needed for lookup_target (LinuxProfile.lookup_target / WindowsProfile.lookup_target).
from profiles import get_profile  # noqa: E402


# ---------------------------------------------------------------------------
# Shell binary → canonical path. Module-specific.
# ---------------------------------------------------------------------------
LINUX_SHELL_BINARY_MAP: dict[str, str] = {
    "bash":   "/bin/bash",
    "sh":     "/bin/sh",
    "dash":   "/bin/dash",
    "zsh":    "/bin/zsh",
    "ksh":    "/bin/ksh",
    "csh":    "/bin/csh",
    "tcsh":   "/bin/tcsh",
    "fish":   "/bin/fish",
}

WINDOWS_SHELL_BINARY_MAP: dict[str, str] = {
    # Wrappers / shells
    "cmd.exe":          "C:\\Windows\\System32\\cmd.exe",
    "cmd":              "C:\\Windows\\System32\\cmd.exe",
    "powershell.exe":   "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "powershell":       "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "pwsh.exe":         "C:\\Program Files\\PowerShell\\7\\pwsh.exe",
    "pwsh":             "C:\\Program Files\\PowerShell\\7\\pwsh.exe",
    # Native tools (used as Image / process_name)
    "reg.exe":          "C:\\Windows\\System32\\reg.exe",
    "reg":              "C:\\Windows\\System32\\reg.exe",
    "wmic.exe":         "C:\\Windows\\System32\\wbem\\wmic.exe",
    "wmic":             "C:\\Windows\\System32\\wbem\\wmic.exe",
    "schtasks.exe":     "C:\\Windows\\System32\\schtasks.exe",
    "schtasks":         "C:\\Windows\\System32\\schtasks.exe",
    "net.exe":          "C:\\Windows\\System32\\net.exe",
    "net":              "C:\\Windows\\System32\\net.exe",
    "tasklist.exe":     "C:\\Windows\\System32\\tasklist.exe",
    "tasklist":         "C:\\Windows\\System32\\tasklist.exe",
    "systeminfo.exe":   "C:\\Windows\\System32\\systeminfo.exe",
    "systeminfo":       "C:\\Windows\\System32\\systeminfo.exe",
    "vssadmin.exe":     "C:\\Windows\\System32\\vssadmin.exe",
    "vssadmin":         "C:\\Windows\\System32\\vssadmin.exe",
    "wevtutil.exe":     "C:\\Windows\\System32\\wevtutil.exe",
    "wevtutil":         "C:\\Windows\\System32\\wevtutil.exe",
    "bcdedit.exe":      "C:\\Windows\\System32\\bcdedit.exe",
    "bcdedit":          "C:\\Windows\\System32\\bcdedit.exe",
    "sc.exe":           "C:\\Windows\\System32\\sc.exe",
    "sc":               "C:\\Windows\\System32\\sc.exe",
    "rundll32.exe":     "C:\\Windows\\System32\\rundll32.exe",
    "rundll32":         "C:\\Windows\\System32\\rundll32.exe",
    # Lateral movement tools (not in System32)
    "psexec.exe":       "C:\\Tools\\psexec.exe",
    "psexec":           "C:\\Tools\\psexec.exe",
    "wmiexec.exe":      "C:\\Tools\\wmiexec.exe",
    "wmiexec":          "C:\\Tools\\wmiexec.exe",
    "mimikatz.exe":     "C:\\Tools\\mimikatz.exe",
    "mimikatz":         "C:\\Tools\\mimikatz.exe",
}

# Splunk's match() / regex call:
#   match(<field>, "<pattern>")
#   regex <field>="<pattern>"
_RE_MATCH_CALL = re.compile(
    r"""match\s*\(\s*[^,]+,\s*['"]([^'"]+)['"]\s*\)""",
    re.IGNORECASE,
)
_RE_REGEX_ASSIGN = re.compile(
    r"""regex\s+\w+\s*=\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)

# Windows image / process-name patterns in SPL:
#   Image="*\\powershell.exe"
#   Image|endswith="\\cmd.exe"
#   process_name="vssadmin.exe"
#   CommandLine="*vssadmin*"
_RE_WINDOWS_IMAGE = re.compile(
    r"""(?:Image|process_name)\s*(?:\|\w+\s*)?=\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
_RE_WINDOWS_CMDLINE = re.compile(
    r"""CommandLine\s*(?:\|\w+\s*)?=\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)


def _extract_linux_a0(spl: str) -> list[str]:
    """Extract the shell binaries from `a0="..."` clauses (Linux/auditd)."""
    bins: list[str] = []
    for m in re.finditer(r"""a0\s*=\s*['"]([^'"]+)['"]""", spl, re.IGNORECASE):
        v = m.group(1).strip()
        if v and v not in bins:
            bins.append(v)
    return bins


def _extract_linux_a1(spl: str) -> str:
    """Extract the shell flag from `a1="..."` (Linux/auditd)."""
    m = re.search(r"""a1\s*=\s*['"]([^'"]+)['"]""", spl, re.IGNORECASE)
    return m.group(1).strip() if m else "-c"


def _extract_windows_bins(spl: str) -> list[str]:
    """Extract process binaries from Windows SPL clauses.

    Recognises `Image=*\\foo.exe`, `Image|endswith="foo.exe"`,
    `process_name="foo.exe"`. Returns just the basename (no path prefix).
    """
    bins: list[str] = []
    for m in _RE_WINDOWS_IMAGE.finditer(spl):
        v = m.group(1).strip()
        # Strip leading *\ and wildcards.
        v = re.sub(r"^[\*\\\s]+", "", v)
        v = v.split("\\")[-1]   # keep last segment
        v = v.split("/")[-1]
        if v and v not in bins:
            bins.append(v)
    if not bins:
        # Fallback to CommandLine — pull first token.
        m = _RE_WINDOWS_CMDLINE.search(spl)
        if m:
            v = m.group(1).strip().strip("*").strip()
            v = v.split()[0] if v.split() else ""
            v = v.split("\\")[-1].split("/")[-1]
            if v and v not in bins:
                bins.append(v)
    return bins


def _extract_windows_flag(spl: str) -> str:
    """Default shell flag for Windows is /c (cmd) or -Command (powershell).

    Heuristic: if the SPL contains 'powershell' or 'pwsh' anywhere, return
    '-Command'; otherwise return '/c'.
    """
    if re.search(r"powershell|pwsh", spl, re.IGNORECASE):
        return "-Command"
    return "/c"


def _extract_target_regex(spl: str) -> str | None:
    """Find the first match() or regex= pattern that contains a useful target."""
    for pat in (_RE_MATCH_CALL, _RE_REGEX_ASSIGN):
        for m in pat.finditer(spl):
            candidate = m.group(1)
            # Heuristic: must contain a slash, dot, backslash, or a recognized marker.
            if any(c in candidate for c in ["/", ".", "\\", "_", "-"]):
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
    """Expand `(a|b|c)` groups into individual tokens."""
    out: list[str] = []
    top = _split_top_level_alternation(pattern)
    for token in top:
        m = re.match(r"^(.*?)\(([^)]+)\)(.*)$", token)
        if m:
            prefix, alts, suffix = m.group(1), m.group(2), m.group(3)
            for alt in _split_top_level_alternation(alts):
                inner = prefix + alt + suffix
                out.extend(_expand_paren_groups(inner))
        else:
            out.append(token)
    return out


def _normalize_target(token: str) -> str:
    """Strip regex anchors, wildcards, and surrounding quotes."""
    t = token.strip().lstrip("^").rstrip("$")
    t = t.strip('*').strip()
    return t


def _slug_for(name: str) -> str:
    """Make a snake_case action name from a target path."""
    s = re.sub(r"[^a-zA-Z0-9]+", "_", name).strip("_").lower()
    return s[:60] or "action"


def parse_spl(text: str, timeout: int = 15, module: str = "linux") -> list[ActionSpec]:
    """Parse an SPL rule and return a list of ActionSpec objects.

    `module` is "linux" or "windows" — picks the target table, shell map,
    and shell-flag default.
    """
    profile = get_profile(module)
    if module == "windows":
        return _parse_spl_windows(text, profile, timeout)
    return _parse_spl_linux(text, profile, timeout)


def _parse_spl_linux(text: str, profile, timeout: int) -> list[ActionSpec]:
    """Original Linux/auditd parser — preserved verbatim."""
    shells = _extract_linux_a0(text)
    if not shells:
        shells = ["bash"]
    flag = _extract_linux_a1(text)
    pattern = _extract_target_regex(text)
    if not pattern:
        return []

    expanded = _expand_paren_groups(pattern)
    specs: list[ActionSpec] = []
    seen: set[str] = set()
    for token in expanded:
        norm = _normalize_target(token)
        row = profile.lookup_target(norm)
        resolved = row.canonical_path
        if resolved in seen:
            continue
        seen.add(resolved)

        display = row.display_name
        name = _slug_for(display)
        specs.append(ActionSpec(
            name=name,
            title=f"{display} via Shell",
            description=(
                f"Simulates shell access to {resolved} in order to exercise "
                f"{row.tactic} {tech_id_only(row.technique, row.sub_technique)} "
                f"({row.ukc_phase})."
            ),
            shell_path=LINUX_SHELL_BINARY_MAP.get(shells[0], f"/bin/{shells[0]}"),
            shell_flag=flag,
            target_path=resolved,
            target_regex=norm,
            timeout=timeout,
            tactic=row.tactic,
            technique=row.technique,
            sub_technique=row.sub_technique,
            ukc_phase=row.ukc_phase,
            is_privileged=row.is_privileged,
            expected_output=row.expected_output,
            binaries=tuple(shells),
            play_path=row.play_path or "",
            play_arguments=row.play_arguments or "",
        ))
    return specs


def _parse_spl_windows(text: str, profile, timeout: int) -> list[ActionSpec]:
    """Windows SPL parser — recognises Image / process_name / CommandLine.

    Combines:
      1. Tokens from any `match()` / `regex=` clause.
      2. Basenames from any `Image=` / `process_name=` clause.

    Each is looked up against the Windows target table; we add one action
    per unique row.  Rows that resolve via Image= use the per-row
    `play_path` / `play_arguments` template (the canonical Windows shape).
    """
    bins = _extract_windows_bins(text)
    if not bins:
        bins = ["cmd.exe"]
    flag = _extract_windows_flag(text)
    pattern = _extract_target_regex(text)

    # Collect candidate tokens from both sources.
    candidates: list[str] = []
    if pattern:
        candidates.extend(_expand_paren_groups(pattern))
    candidates.extend(bins)  # Image names as fallback target tokens.

    specs: list[ActionSpec] = []
    seen: set[str] = set()
    for token in candidates:
        norm = _normalize_target(token)
        # Skip noise tokens (pure wildcards, empty).
        if not norm or norm in {"*", "?", "<unknown>"}:
            continue
        row = profile.lookup_target(norm)
        # Skip the fallback row unless we have nothing else.
        if row.target_regex == "<unknown>":
            continue
        if row.target_regex in seen:
            continue
        seen.add(row.target_regex)

        # Pick the most relevant bin to associate as `binaries`.
        primary_bin = bins[0] if bins else "cmd.exe"
        # If the resolved row's play_path uses a specific binary, prefer that.
        # (e.g., vssadmin.exe for the vssadmin row.)

        shell_path = WINDOWS_SHELL_BINARY_MAP.get(primary_bin, f"C:\\Windows\\System32\\{primary_bin}")

        name = _slug_for(row.display_name)
        specs.append(ActionSpec(
            name=name,
            title=row.display_name,
            description=(
                f"Detects {primary_bin} activity matching '{norm}' in order to "
                f"exercise {row.tactic} {tech_id_only(row.technique, row.sub_technique)} "
                f"({row.ukc_phase})."
            ),
            shell_path=shell_path,
            shell_flag=flag,
            target_path=row.canonical_path,
            target_regex=norm,
            timeout=timeout,
            tactic=row.tactic,
            technique=row.technique,
            sub_technique=row.sub_technique,
            ukc_phase=row.ukc_phase,
            is_privileged=row.is_privileged,
            expected_output=row.expected_output,
            binaries=tuple(bins),
            play_path=row.play_path or "",
            play_arguments=row.play_arguments or "",
        ))
    return specs


def main() -> None:
    p = argparse.ArgumentParser(description="Parse a Splunk SPL rule into ActionSpec JSON.")
    p.add_argument("input", help="Path to SPL file or '-' for stdin")
    p.add_argument("--module", default="linux", choices=["linux", "windows"],
                   help="Module (default: linux).")
    p.add_argument("--timeout", type=int, default=15)
    args = p.parse_args()

    if args.input == "-":
        text = sys.stdin.read()
    else:
        text = Path(args.input).read_text(encoding="utf-8", errors="replace")

    specs = parse_spl(text, timeout=args.timeout, module=args.module)
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
            "play_path": s.play_path,
            "play_arguments": s.play_arguments,
            "module": args.module,
            "os_name": "Windows" if args.module == "windows" else "Linux",
        }
        out.append(d)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
