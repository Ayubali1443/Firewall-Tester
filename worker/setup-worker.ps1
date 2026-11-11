<#
.SYNOPSIS
    Deploys the SentinelGate AI Cloudflare Worker Relay and pushes secrets cleanly from root .env.
.DESCRIPTION
    Reads ACCOUNT_ID (or CF_ACCOUNT_ID), API_TOKEN (or CF_API_TOKEN), and RELAY_CLIENT_SECRET
    from ..\.env, generates a strong RELAY_CLIENT_SECRET if empty, runs `npx wrangler deploy`,
    pushes all 3 encrypted Worker Secrets via stdin (no secret args in process list), and updates
    WORKER_URL in ..\.env when detected from Wrangler output.
#>
$ErrorActionPreference = "Stop"

$WorkerDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $WorkerDir
$EnvFile = Join-Path $RootDir ".env"

if (-not (Test-Path $EnvFile)) {
    throw "Missing $EnvFile. Copy .env.example to .env and fill in ACCOUNT_ID and API_TOKEN first."
}

function Read-DotEnv([string]$Path) {
    $map = @{}
    foreach ($rawLine in Get-Content -LiteralPath $Path -Encoding UTF8) {
        $line = $rawLine.Trim()
        if (-not $line -or $line.StartsWith("#")) { continue }
        $idx = $line.IndexOf("=")
        if ($idx -lt 1) { continue }
        $k = $line.Substring(0, $idx).Trim()
        $v = $line.Substring($idx + 1).Trim()
        if (($v.StartsWith('"') -and $v.EndsWith('"')) -or ($v.StartsWith("'") -and $v.EndsWith("'"))) {
            if ($v.Length -ge 2) { $v = $v.Substring(1, $v.Length - 2) }
        }
        $map[$k] = $v
    }
    return $map
}

function Set-DotEnvKey([string]$Path, [string]$Key, [string]$Val) {
    $lines = Get-Content -LiteralPath $Path -Encoding UTF8
    $updated = $false
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match "^\s*$([regex]::Escape($Key))\s*=") {
            $lines[$i] = "$Key=`"$Val`""
            $updated = $true
            break
        }
    }
    if (-not $updated) {
        $lines += "$Key=`"$Val`""
    }
    Set-Content -LiteralPath $Path -Value $lines -Encoding UTF8
}

$envVars = Read-DotEnv $EnvFile
$AcctId = if ($envVars["CF_ACCOUNT_ID"]) { $envVars["CF_ACCOUNT_ID"] } else { $envVars["ACCOUNT_ID"] }
$ApiToken = if ($envVars["CF_API_TOKEN"]) { $envVars["CF_API_TOKEN"] } else { $envVars["API_TOKEN"] }
$RelaySecret = if ($envVars["RELAY_CLIENT_SECRET"]) { $envVars["RELAY_CLIENT_SECRET"] } else { $envVars["SG_WORKER_TOKEN"] }

if ([string]::IsNullOrWhiteSpace($AcctId) -or [string]::IsNullOrWhiteSpace($ApiToken)) {
    throw "ACCOUNT_ID and API_TOKEN must be populated in .env before deploying the Worker relay."
}

if ([string]::IsNullOrWhiteSpace($RelaySecret)) {
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] 36
    $rng.GetBytes($bytes)
    $RelaySecret = [Convert]::ToBase64String($bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=')
    Set-DotEnvKey $EnvFile "RELAY_CLIENT_SECRET" $RelaySecret
    Write-Host "[*] Generated high-entropy RELAY_CLIENT_SECRET and saved to .env"
}

Push-Location $WorkerDir
try {
    Write-Host "[1/2] Deploying sentinelgate-relay Worker via Wrangler..."
    $deployOut = & npx wrangler deploy 2>&1
    $deployOut | ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -ne 0) {
        throw "npx wrangler deploy failed (run 'npx wrangler login' first if not authenticated)."
    }

    $detectedUrl = ""
    foreach ($line in $deployOut) {
        if ($line -match "(https://[a-zA-Z0-9._-]+\.workers\.dev)") {
            $detectedUrl = $Matches[1]
        }
    }
    if ($detectedUrl) {
        Set-DotEnvKey $EnvFile "WORKER_URL" $detectedUrl
        Write-Host "[*] Updated WORKER_URL in .env -> $detectedUrl"
    }

    Write-Host "[2/2] Pushing encrypted Worker Secrets from .env (CF_ACCOUNT_ID, CF_API_TOKEN, RELAY_CLIENT_SECRET)..."
    $AcctId | & npx wrangler secret put CF_ACCOUNT_ID
    if ($LASTEXITCODE -ne 0) { throw "Failed setting CF_ACCOUNT_ID secret." }

    $ApiToken | & npx wrangler secret put CF_API_TOKEN
    if ($LASTEXITCODE -ne 0) { throw "Failed setting CF_API_TOKEN secret." }

    $RelaySecret | & npx wrangler secret put RELAY_CLIENT_SECRET
    if ($LASTEXITCODE -ne 0) { throw "Failed setting RELAY_CLIENT_SECRET secret." }

    Write-Host ""
    Write-Host "[DONE] Worker relay deployed and encrypted secrets uploaded cleanly!" -ForegroundColor Green
    if ($detectedUrl) {
        Write-Host "Next step: build the client installer with:  .\.venv\Scripts\python.exe build.py"
    } else {
    Write-Host "Next step: install/run SentinelGate AI, then enter the deployed Worker URL and matching relay key in API Vault & Security."
    }
} finally {
    Pop-Location
}
