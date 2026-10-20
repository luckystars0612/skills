#Requires -Version 5.1
<#
.SYNOPSIS
    Install every skill in this repo into MiniMax Code (mcode).

.DESCRIPTION
    Skills -> $env:MINIMAX_HOME\skills\<name>\   (default: ~\.minimax\skills)

    A skill is any top-level directory that contains a SKILL.md; its whole
    directory is copied. mcode has no user-level slash-command directory, so a
    skill's commands\ folder is copied with it but is only reachable through the
    skill's own /<name> invocation.

    mcode also auto-discovers ~\.claude\skills, ~\.codex\skills, ~\.agents\skills
    and the per-workspace .minimax|.claude|.agents\skills (skills.external in
    config.yaml, on by default). Installing here makes the skills mcode-native,
    so they keep working with external discovery turned off or without Claude
    Code installed. A same-named ~\.claude\skills copy still shadows this one
    (user source priority 40 vs global 0) - identical content, so it does not matter.

.PARAMETER DryRun
    Show what would happen without changing anything.

.EXAMPLE
    .\install-mcode.ps1
    .\install-mcode.ps1 -DryRun
    $env:MINIMAX_HOME = 'D:\minimax'; .\install-mcode.ps1

.NOTES
    If script execution is blocked, run once:
      powershell -ExecutionPolicy Bypass -File .\install-mcode.ps1
#>
[CmdletBinding()]
param([switch]$DryRun)

$ErrorActionPreference = 'Stop'

$RepoDir = $PSScriptRoot
if ($env:MINIMAX_HOME) { $MinimaxHome = $env:MINIMAX_HOME }
elseif ($env:MINIMAX_DATA_DIR) { $MinimaxHome = $env:MINIMAX_DATA_DIR }
else { $MinimaxHome = Join-Path $HOME '.minimax' }
$SkillsDst = Join-Path $MinimaxHome 'skills'

Write-Host "Repo:         $RepoDir"
Write-Host "MiniMax home: $MinimaxHome"
if ($DryRun) { Write-Host "(dry run - no changes made)" }

if ($DryRun) { Write-Host "  [dry-run] mkdir $SkillsDst" }
elseif (-not (Test-Path $SkillsDst)) { New-Item -ItemType Directory -Force -Path $SkillsDst | Out-Null }

$skillDirs = Get-ChildItem -Path $RepoDir -Directory |
    Where-Object { Test-Path (Join-Path $_.FullName 'SKILL.md') }

$installed = 0
foreach ($d in $skillDirs) {
    $skillDir = $d.FullName
    $name = $d.Name
    $skillMd = Join-Path $skillDir 'SKILL.md'

    # mcode requires frontmatter `name` == directory name, lowercase slug only.
    $fmName = (Select-String -Path $skillMd -Pattern '^name:\s*(.+)$' |
        Select-Object -First 1).Matches.Groups[1].Value
    if ($fmName) { $fmName = $fmName.Trim().Trim('"').Trim("'") }
    if ($fmName -ne $name) {
        Write-Host ""
        Write-Host "== $name == SKIPPED: frontmatter name '$fmName' != directory name"
        continue
    }

    Write-Host ""
    Write-Host "== $name =="
    $dest = Join-Path $SkillsDst $name
    if ($DryRun) {
        Write-Host "  [dry-run] copy skill -> $dest"
    } else {
        if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
        Copy-Item -Recurse -Force -Path $skillDir -Destination $dest
        Write-Host "  skill -> $dest"
    }
    $installed++
}

Write-Host ""
Write-Host "Done. Installed $installed skill(s) for mcode."
Write-Host "Start a new mcode session to pick them up (/skills lists them)."
