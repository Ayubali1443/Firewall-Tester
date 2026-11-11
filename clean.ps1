<#
.SYNOPSIS
    Cleans all regenerable dependencies, caches, and build artifacts for a clean production repository.
.PARAMETER KeepDist
    Keep the compiled dist/SentinelGateAI.exe output if present.
#>
param(
    [switch]$KeepDist
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

Write-Host "=== SentinelGate AI - Cleaning Dependencies & Build Artifacts ===" -ForegroundColor Cyan

$DirTargets = @(
    ".venv",
    "venv",
    "env",
    "node_modules",
    "build",
    "main.build",
    "main.dist",
    "main.onefile-build",
    ".pytest_cache",
    "reports",
    "worker\.wrangler",
    "sentinelgate\config\_seal_build",
    "sentinelgate\validator\target",
    "sentinelgate\validator\bin"
)

if (-not $KeepDist) {
    $DirTargets += "dist"
}

foreach ($rel in $DirTargets) {
    $targetPath = Join-Path $Root $rel
    if (Test-Path $targetPath) {
        Write-Host "  [-] Removing $rel" -ForegroundColor Yellow
        Remove-Item -Recurse -Force $targetPath
    }
}

# Recursively remove Python __pycache__, *.egg-info, and nested node_modules
Get-ChildItem -Path $Root -Recurse -Directory -Force -ErrorAction SilentlyContinue |
    Where-Object {
        $_.FullName -notmatch '\\\.git(\\|$)' -and
        ($_.Name -in @("__pycache__", "node_modules", ".pytest_cache") -or $_.Name -like "*.egg-info")
    } |
    ForEach-Object {
        Write-Host "  [-] Removing $($_.FullName.Substring($Root.Length + 1))" -ForegroundColor Yellow
        Remove-Item -Recurse -Force $_.FullName -ErrorAction SilentlyContinue
    }

# Remove compiled Python bytecode, crash reports, and transient sealed files
Get-ChildItem -Path $Root -Recurse -File -Force -ErrorAction SilentlyContinue |
    Where-Object {
        $_.FullName -notmatch '\\\.git(\\|$)' -and
        ($_.Extension -in @(".pyc", ".pyo", ".spec") -or $_.Name -in @("nuitka-crash-report.xml", "_sealed_cf.py") -or $_.Name -like "sg_seal.*")
    } |
    ForEach-Object {
        Write-Host "  [-] Removing $($_.FullName.Substring($Root.Length + 1))" -ForegroundColor Yellow
        Remove-Item -Force $_.FullName -ErrorAction SilentlyContinue
    }

Write-Host "[OK] Workspace cleaned. Only tracked source files and baseline data remain." -ForegroundColor Green
