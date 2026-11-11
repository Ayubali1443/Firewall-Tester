<#
.SYNOPSIS
    Single-file developer & production setup script for SentinelGate AI.
    Installs missing Python/Rust toolchains, creates .venv, installs Python packages,
    Compiles Rust cf_validator.exe, prompts via Administrator UAC for Cloudflare & Gemini APIs
    (locking Cloudflare credentials so standard desktop users cannot access them), runs tests,
    and optionally builds SentinelGateAI-Setup.exe.
.PARAMETER BuildSetup
    Also compile the single self-contained SentinelGateAI-Setup.exe installer (with Rust & app embedded).
.PARAMETER BuildExe
    Alias for -BuildSetup.
.PARAMETER SkipTests
    Skip running the automated unittest suite.
.PARAMETER SkipCredentials
    Skip interactive Cloudflare & Gemini API credential setup.
#>
param(
    [switch]$BuildSetup,
    [switch]$BuildExe,
    [switch]$SkipTests,
    [switch]$SkipCredentials
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

function Assert-LastExit($StepName) {
    if ($LASTEXITCODE -ne 0) {
        throw "$StepName failed with exit code $LASTEXITCODE"
    }
}

Write-Host "=== SentinelGate AI - Unified Single-Script Setup ===" -ForegroundColor Cyan

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
    Write-Host "[4/5] Running automated unit & security test suite..." -ForegroundColor Cyan
    & $VenvPython -m unittest discover -s tests -v
    Assert-LastExit "unittest"
} else {
    Write-Host "[4/5] Skipping unit tests (-SkipTests set)." -ForegroundColor Yellow
}

if (-not $SkipCredentials) {
    Write-Host "[5/5] Configuring Cloudflare & Gemini APIs (UAC Administrator Lock for Cloudflare)..." -ForegroundColor Cyan
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if ($isAdmin) {
        & $VenvPython -m sentinelgate.config.cf_secrets --interactive-setup
        Assert-LastExit "interactive-setup"
    } else {
        Write-Host "  Requesting Windows Administrator UAC elevation to seal Cloudflare credentials..." -ForegroundColor Yellow
        try {
            $proc = Start-Process -FilePath $VenvPython -ArgumentList "-m", "sentinelgate.config.cf_secrets", "--interactive-setup" -WorkingDirectory $Root -Verb RunAs -PassThru -Wait
            if ($proc.ExitCode -ne 0) {
                throw "Elevated credential setup exited with code $($proc.ExitCode)"
            }
        } catch {
            Write-Host "  [!] Administrator UAC elevation was cancelled or failed: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "      Cloudflare API remains locked until Administrator setup completes." -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "[5/5] Skipping interactive credential setup (-SkipCredentials set)." -ForegroundColor Yellow
}

if ($BuildSetup -or $BuildExe) {
    Write-Host "[PROD] Compiling single self-contained SentinelGateAI-Setup.exe..." -ForegroundColor Cyan
    & $VenvPython (Join-Path $Root "build.py") --backend nuitka --only-setup-file
    Assert-LastExit "build.py"
}

Write-Host "[OK] SentinelGate AI environment is ready." -ForegroundColor Green
