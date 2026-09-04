#Requires -Version 5.1
<#
.SYNOPSIS
    Install every skill in this repo (plus its slash commands) into Claude Code.

.DESCRIPTION
    Skills   -> $env:CLAUDE_HOME\skills\<name>\    (default: ~\.claude\skills)
    Commands -> $env:CLAUDE_HOME\commands\<cmd>.md  (default: ~\.claude\commands)

    A skill is any top-level directory that contains a SKILL.md. Its whole
    directory is copied under skills\, and any commands\*.md (except README.md)
    is also dropped into commands\ so the /<name> slash command works.

.PARAMETER DryRun
    Show what would happen without changing anything.

.EXAMPLE
    .\install.ps1
    .\install.ps1 -DryRun
    $env:CLAUDE_HOME = 'D:\claude'; .\install.ps1

.NOTES
    If script execution is blocked, run once:
      powershell -ExecutionPolicy Bypass -File .\install.ps1
#>
[CmdletBinding()]
param([switch]$DryRun)

$ErrorActionPreference = 'Stop'

$RepoDir = $PSScriptRoot
if ($env:CLAUDE_HOME) { $ClaudeHome = $env:CLAUDE_HOME }
else { $ClaudeHome = Join-Path $HOME '.claude' }
$SkillsDst = Join-Path $ClaudeHome 'skills'
$CmdsDst   = Join-Path $ClaudeHome 'commands'

Write-Host "Repo:        $RepoDir"
Write-Host "Claude home: $ClaudeHome"
if ($DryRun) { Write-Host "(dry run - no changes made)" }

function Ensure-Dir($p) {
    if ($DryRun) { Write-Host "  [dry-run] mkdir $p" }
    elseif (-not (Test-Path $p)) { New-Item -ItemType Directory -Force -Path $p | Out-Null }
}

Ensure-Dir $SkillsDst
Ensure-Dir $CmdsDst

$skillDirs = Get-ChildItem -Path $RepoDir -Directory |
    Where-Object { Test-Path (Join-Path $_.FullName 'SKILL.md') }

foreach ($d in $skillDirs) {
    $skillDir = $d.FullName
    $name = $d.Name
    Write-Host ""
    Write-Host "== $name =="

    # 1) install the whole skill directory
    $dest = Join-Path $SkillsDst $name
    if ($DryRun) {
        Write-Host "  [dry-run] copy skill -> $dest"
    } else {
        if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
        Copy-Item -Recurse -Force -Path $skillDir -Destination $dest
        Write-Host "  skill   -> $dest"
    }

    # 2) install its slash commands (skip README.md)
    $cmdDir = Join-Path $skillDir 'commands'
    if (Test-Path $cmdDir) {
        Get-ChildItem -Path $cmdDir -Filter *.md |
            Where-Object { $_.Name -ne 'README.md' } |
            ForEach-Object {
                $target = Join-Path $CmdsDst $_.Name
                if ($DryRun) { Write-Host "  [dry-run] copy command -> $target" }
                else {
                    Copy-Item -Force -Path $_.FullName -Destination $target
                    Write-Host "  command -> $target"
                }
            }
    }
}

Write-Host ""
Write-Host "Done. Installed $($skillDirs.Count) skill(s)."
Write-Host "Start a new Claude Code session (or restart) to pick them up."
