<#
.SYNOPSIS
    Reinstalls Python dependencies (.venv), compiles Rust cf_validator.exe, and runs verification tests.
.PARAMETER BuildExe
    Also compile the production standalone Windows executable via Nuitka (requires CF_ACCOUNT_ID & CF_API_TOKEN).
.PARAMETER SkipTests
    Skip running the automated unittest suite after installation.
#>
param(
    [switch]$BuildExe,
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

Write-Host "=== SentinelGate AI - Reinstalling Dependencies & Building Validator ===" -ForegroundColor Cyan

$VenvDir = Join-Path $Root ".venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"

if (-not (Test-Path $VenvPython)) {
    Write-Host "[1/4] Creating isolated Python virtual environment (.venv)..." -ForegroundColor Cyan
    python -m venv $VenvDir
} else {
    Write-Host "[1/4] Using existing virtual environment (.venv)..." -ForegroundColor Cyan
}

Write-Host "[2/4] Upgrading pip and installing requirements.txt..." -ForegroundColor Cyan
& $VenvPython -m pip install --upgrade pip
& $VenvPython -m pip install -r (Join-Path $Root "requirements.txt")

Write-Host "[3/4] Compiling Rust cf_validator.exe and updating SHA-256 checksum..." -ForegroundColor Cyan
& $VenvPython -c "import build; build.build_rust_validator()"

if (-not $SkipTests) {
    Write-Host "[4/4] Running automated unit & security test suite..." -ForegroundColor Cyan
    & $VenvPython -m unittest discover -s tests -v
} else {
    Write-Host "[4/4] Skipping unit tests (-SkipTests set)." -ForegroundColor Yellow
}

if ($BuildExe) {
    Write-Host "[PROD] Compiling production standalone executable (dist\SentinelGateAI.exe)..." -ForegroundColor Cyan
    & $VenvPython (Join-Path $Root "build.py") --backend nuitka
}

Write-Host "[OK] SentinelGate AI environment is ready." -ForegroundColor Green
