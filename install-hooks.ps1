#Requires -Version 5.1
<#
.SYNOPSIS
    Install Claude Code hooks (research state auto-restore).

.DESCRIPTION
    Scripts  -> $CLAUDE_HOME\scripts\         (default: ~\.claude\scripts)
    Hooks    -> merged into ~\.claude\settings.json

    Installs inject_state.py and adds PostCompact + SessionStart hooks
    so RESEARCH_STATE.md is auto-injected after compaction / session start.

.PARAMETER DryRun
    Show what would happen without changing anything.

.PARAMETER Uninstall
    Remove the hooks and script.

.EXAMPLE
    .\install-hooks.ps1
    .\install-hooks.ps1 -DryRun
    .\install-hooks.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'

$RepoDir = $PSScriptRoot
if ($env:CLAUDE_HOME) { $ClaudeHome = $env:CLAUDE_HOME }
else { $ClaudeHome = Join-Path $HOME '.claude' }
$ScriptsDst  = Join-Path $ClaudeHome 'scripts'
$SettingsFile = Join-Path $ClaudeHome 'settings.json'
$ScriptName   = 'inject_state.py'
$ScriptSrc    = Join-Path (Join-Path $RepoDir 'hooks') $ScriptName

Write-Host "Repo:        $RepoDir"
Write-Host "Claude home: $ClaudeHome"
if ($DryRun) { Write-Host "(dry run - no changes made)" }

# --- Uninstall ---
if ($Uninstall) {
    $target = Join-Path $ScriptsDst $ScriptName
    if (Test-Path $target) {
        if ($DryRun) { Write-Host "  [dry-run] remove $target" }
        else { Remove-Item -Force $target; Write-Host "  removed $target" }
    }
    if (Test-Path $SettingsFile) {
        if ($DryRun) { Write-Host "  [dry-run] remove hooks from settings.json" }
        else {
            # NOTE: `python -c @'...'@` does NOT work -- PowerShell 5.1 strips the
            # quotes when passing a here-string to a native exe, so the code fails
            # with a SyntaxError. Always go through a temp .py file.
            $py = @'
import json, os, sys
p = sys.argv[1]
with open(p, "r") as f: s = json.load(f)
h = s.get("hooks", {})
h.pop("PostCompact", None); h.pop("SessionStart", None)
if not h: s.pop("hooks", None)
with open(p, "w") as f: json.dump(s, f, indent=2)
'@
            $tmp = Join-Path ([System.IO.Path]::GetTempPath()) 'claude_hooks_uninstall.py'
            Set-Content -Path $tmp -Value $py -Encoding utf8
            python -I $tmp $SettingsFile
            if ($LASTEXITCODE -ne 0) { Remove-Item -Force $tmp; throw "failed to update $SettingsFile" }
            Remove-Item -Force $tmp
            Write-Host "  removed hooks from settings.json"
        }
    }
    Write-Host "`nDone. Hooks uninstalled."
    return
}

# --- Install script ---
if (-not (Test-Path $ScriptsDst)) {
    if ($DryRun) { Write-Host "  [dry-run] mkdir $ScriptsDst" }
    else { New-Item -ItemType Directory -Force -Path $ScriptsDst | Out-Null }
}

$target = Join-Path $ScriptsDst $ScriptName
if ($DryRun) { Write-Host "  [dry-run] copy $ScriptName -> $target" }
else {
    Copy-Item -Force -Path $ScriptSrc -Destination $target
    Write-Host "  script -> $target"
}

# --- Merge hooks into settings.json ---
if ($DryRun) {
    Write-Host "  [dry-run] merge hooks into settings.json"
} else {
    # NOTE: temp .py file, not `python -c @'...'@` -- see the comment in the
    # uninstall branch for why.
    $py = @'
import json, os, sys

settings_path = sys.argv[1]
if os.path.exists(settings_path):
    with open(settings_path, "r") as f:
        settings = json.load(f)
else:
    settings = {}

# NOTE: no `echo '{}' |` prefix -- the script must receive Claude Code's real
# stdin payload so it can read hook_event_name and echo it back.
hook_cmd = "python -I \"$HOME/.claude/scripts/inject_state.py\" 2>/dev/null || echo '{}'"

hooks = settings.setdefault("hooks", {})
hooks["PostCompact"] = [{
    "matcher": "auto",
    "hooks": [{
        "type": "command",
        "command": hook_cmd,
        "timeout": 10,
        "statusMessage": "Restoring research state..."
    }]
}]
hooks["SessionStart"] = [{
    "hooks": [{
        "type": "command",
        "command": hook_cmd,
        "timeout": 10,
        "statusMessage": "Loading research state..."
    }]
}]

with open(settings_path, "w") as f:
    json.dump(settings, f, indent=2)
'@
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) 'claude_hooks_install.py'
    Set-Content -Path $tmp -Value $py -Encoding utf8
    python -I $tmp $SettingsFile
    if ($LASTEXITCODE -ne 0) { Remove-Item -Force $tmp; throw "failed to update $SettingsFile" }
    Remove-Item -Force $tmp
    Write-Host "  hooks  -> $SettingsFile"
}

Write-Host ""
Write-Host "Done. Hooks installed."
Write-Host "Any project with a RESEARCH_STATE.md in its root will auto-restore context."
Write-Host "Restart Claude Code to pick up the new hooks."
