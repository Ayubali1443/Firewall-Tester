<#
.SYNOPSIS
    Environment setup script for SentinelGate AI.
    Installs missing Python/Rust toolchains, creates .venv, installs Python packages,
    compiles Rust cf_validator.exe, and runs the test suite.
.PARAMETER SkipTests
    Skip running the automated unittest suite.
#>
param(
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

function Assert-LastExit($StepName) {
    if ($LASTEXITCODE -ne 0) {
        throw "$StepName failed with exit code $LASTEXITCODE"
    }
}

Write-Host "=== SentinelGate AI - Environment Setup ===" -ForegroundColor Cyan

# 1. Ensure Python 3.12+ is available
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "[Pre-Req] Python not found. Attempting installation via winget..." -ForegroundColor Yellow
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install -e --id Python.Python.3.12 --accept-package-agreements --accept-source-agreements
        $env:PATH = "$env:LOCALAPPDATA\Programs\Python\Python312;$env:LOCALAPPDATA\Programs\Python\Python312\Scripts;$env:PATH"
    } else {
        throw "Python is required. Install Python 3.12+ and re-run setup.ps1."
    }
}

# 2. Ensure Rust (cargo + rustc) is available
$CargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
if (Test-Path $CargoBin) {
    $env:PATH = "$CargoBin;$env:PATH"
}
if (-not (Get-Command cargo -ErrorAction SilentlyContinue) -or -not (Get-Command rustc -ErrorAction SilentlyContinue)) {
    Write-Host "[Pre-Req] Rust toolchain not found. Installing Rust (rustup)..." -ForegroundColor Yellow
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install -e --id Rustlang.Rustup --accept-package-agreements --accept-source-agreements
    } else {
        $rustupExe = Join-Path $env:TEMP "rustup-init.exe"
        Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $rustupExe -UseBasicParsing
        & $rustupExe -y
        Assert-LastExit "rustup-init"
    }
    $env:PATH = "$CargoBin;$env:PATH"
}

$VenvDir = Join-Path $Root ".venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"

if (-not (Test-Path $VenvPython)) {
    Write-Host "[1/4] Creating isolated Python virtual environment (.venv)..." -ForegroundColor Cyan
    python -m venv $VenvDir
    Assert-LastExit "python -m venv"
} else {
    Write-Host "[1/4] Using existing virtual environment (.venv)..." -ForegroundColor Cyan
}

Write-Host "[2/4] Upgrading pip and installing requirements.txt..." -ForegroundColor Cyan
& $VenvPython -m pip install --upgrade pip
Assert-LastExit "pip upgrade"
& $VenvPython -m pip install -r (Join-Path $Root "requirements.txt")
Assert-LastExit "pip install requirements"

Write-Host "[3/4] Compiling Rust cf_validator.exe and updating SHA-256 checksum..." -ForegroundColor Cyan
& $VenvPython -c "import build; build.build_rust_validator()"
Assert-LastExit "build_rust_validator"

if (-not $SkipTests) {
    Write-Host "[4/4] Running automated unit & security test suite..." -ForegroundColor Cyan
    & $VenvPython -m unittest discover -s tests -v
    Assert-LastExit "unittest"
} else {
    Write-Host "[4/4] Skipping unit tests (-SkipTests set)." -ForegroundColor Yellow
}

Write-Host "[OK] SentinelGate AI environment is ready. Run '.\.venv\Scripts\python.exe build.py' to build SentinelGateAI-Setup.exe." -ForegroundColor Green
