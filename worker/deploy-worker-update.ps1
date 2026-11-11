<#
.SYNOPSIS
    Safely deploys a code-only update to the existing SentinelGate Worker Relay.
.DESCRIPTION
    This script never changes Worker secrets or Cloudflare policies/lists. It checks
    the current relay first, syntax-checks and dry-runs the Worker, deploys it, then
    verifies authenticated health, unauthenticated rejection, and DELETE rejection.
    It attempts a Wrangler rollback if any post-deploy check fails.
#>
[CmdletBinding()]
param(
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$WorkerDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $WorkerDir
$EnvFile = Join-Path $RootDir ".env"
$ConfigFile = Join-Path $WorkerDir "wrangler.toml"
$WorkerName = "sentinelgate-relay"

function Read-DotEnv([string]$Path) {
    $map = @{}
    foreach ($rawLine in Get-Content -LiteralPath $Path -Encoding UTF8) {
        $line = $rawLine.Trim()
        if (-not $line -or $line.StartsWith("#")) { continue }
        $idx = $line.IndexOf("=")
        if ($idx -lt 1) { continue }
        $key = $line.Substring(0, $idx).Trim()
        $value = $line.Substring($idx + 1).Trim()
        if (($value.StartsWith('"') -and $value.EndsWith('"')) -or
            ($value.StartsWith("'") -and $value.EndsWith("'"))) {
            if ($value.Length -ge 2) { $value = $value.Substring(1, $value.Length - 2) }
        }
        $map[$key] = $value
    }
    return $map
}

function Invoke-RelayProbe([string]$Uri, [string]$Method = "GET", [switch]$Authenticated) {
    $headers = @{}
    if ($Authenticated) { $headers["X-SG-Relay-Key"] = $RelaySecret }
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $Uri -Method $Method -Headers $headers -TimeoutSec 20
        return @{ Status = [int]$response.StatusCode; Body = [string]$response.Content }
    } catch {
        $response = $_.Exception.Response
        if (-not $response) { throw }
        $status = 0
        $body = ""
        if ($response.GetType().FullName -eq "System.Net.Http.HttpResponseMessage") {
            $status = [int]$response.StatusCode
            $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        } else {
            $status = [int]$response.StatusCode
            try {
                $reader = [System.IO.StreamReader]::new($response.GetResponseStream())
                $body = $reader.ReadToEnd()
                $reader.Dispose()
            } catch { }
        }
        return @{ Status = $status; Body = $body }
    }
}

function Invoke-NativeCommand([scriptblock]$Command) {
    $previousPreference = $ErrorActionPreference
    try {
        # Windows PowerShell 5 can surface native stderr (for example, npm's
        # first-run notice) as a terminating ErrorRecord when preference is Stop.
        $ErrorActionPreference = "Continue"
        $output = & $Command 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    return @{ Output = $output; ExitCode = $exitCode }
}

function Test-Relay([switch]$CheckDeleteGuards) {
    $unauth = Invoke-RelayProbe -Uri "$WorkerUrl/v1/health"
    if ($unauth.Status -ne 401) {
        throw "Relay auth check failed: unauthenticated health request returned HTTP $($unauth.Status), expected 401."
    }

    $healthResponse = Invoke-RelayProbe -Uri "$WorkerUrl/v1/health" -Authenticated
    if ($healthResponse.Status -ne 200) {
        throw "Authenticated relay health check failed with HTTP $($healthResponse.Status)."
    }
    try { $health = $healthResponse.Body | ConvertFrom-Json } catch {
        throw "Relay health endpoint returned invalid JSON."
    }
    if ($health.ok -ne $true -or $null -eq $health.rule_count -or $null -eq $health.list_count) {
        throw "Relay health check did not confirm successful Gateway rule and list access."
    }
    Write-Host "[OK] Relay health: $($health.rule_count) rules, $($health.list_count) lists; unauthenticated access rejected." -ForegroundColor Green

    if ($CheckDeleteGuards) {
        $probeId = "00000000-0000-0000-0000-000000000001"
        $deleteUris = @(
            "$WorkerUrl/v1/rules/$probeId",
            "$WorkerUrl/v1/lists/$probeId",
            "$WorkerUrl/v1/lists/$probeId/items"
        )
        foreach ($uri in $deleteUris) {
            $probe = Invoke-RelayProbe -Uri $uri -Method "DELETE" -Authenticated
            if ($probe.Status -ne 403) {
                throw "DELETE guard check failed for $uri (HTTP $($probe.Status), expected 403)."
            }
        }
        Write-Host "[OK] DELETE requests for policies, lists, and list items are rejected (403)." -ForegroundColor Green
    }
}

if (-not (Test-Path -LiteralPath $EnvFile)) {
    throw "Missing root .env. Copy .env.example to .env and set WORKER_URL and RELAY_CLIENT_SECRET."
}
if (-not (Test-Path -LiteralPath $ConfigFile)) { throw "Missing worker/wrangler.toml." }
if (-not (Get-Command node -ErrorAction SilentlyContinue)) { throw "Node.js is required. Install Node.js 18 or later." }
if (-not (Get-Command npx -ErrorAction SilentlyContinue)) { throw "npx is unavailable. Reinstall Node.js with npm." }

$envVars = Read-DotEnv $EnvFile
$WorkerUrl = ([string]$envVars["WORKER_URL"]).Trim().TrimEnd("/")
$RelaySecret = [string]$envVars["RELAY_CLIENT_SECRET"]
if ([string]::IsNullOrWhiteSpace($WorkerUrl) -or [string]::IsNullOrWhiteSpace($RelaySecret)) {
    throw "WORKER_URL and RELAY_CLIENT_SECRET must be set in root .env. Secrets are read locally and never printed or changed."
}
if ($WorkerUrl -notmatch '^https://[a-zA-Z0-9.-]+\.workers\.dev$') {
    throw "WORKER_URL must be the existing https://<worker>.workers.dev address; got an invalid or unexpected URL."
}

Push-Location $WorkerDir
$deployed = $false
try {
    Write-Host "[1/4] Checking the currently deployed relay before any changes..."
    Test-Relay -CheckDeleteGuards

    Write-Host "[2/4] Checking Worker JavaScript syntax and Wrangler dry run..."
    $nodeCheck = Invoke-NativeCommand { & node --check (Join-Path $WorkerDir "sentinelgate-relay.js") }
    $nodeCheck.Output | ForEach-Object { Write-Host $_ }
    if ($nodeCheck.ExitCode -ne 0) { throw "Worker JavaScript syntax check failed; nothing was deployed." }
    $dryRunResult = Invoke-NativeCommand { & npx wrangler deploy --config $ConfigFile --dry-run }
    $dryRunResult.Output | ForEach-Object { Write-Host $_ }
    if ($dryRunResult.ExitCode -ne 0) { throw "Wrangler dry run failed; nothing was deployed." }

    if ($DryRun) {
        Write-Host "[DRY RUN] Checks passed. No Worker version was deployed and no Cloudflare data was changed." -ForegroundColor Green
        return
    }

    Write-Host "[3/4] Deploying Worker code only. Existing encrypted Worker secrets are left unchanged..."
    $deployResult = Invoke-NativeCommand { & npx wrangler deploy --config $ConfigFile }
    $deployResult.Output | ForEach-Object { Write-Host $_ }
    if ($deployResult.ExitCode -ne 0) { throw "Wrangler deployment failed. The prior active deployment remains in place." }
    $deployed = $true

    Write-Host "[4/4] Verifying the deployed relay and deletion guards..."
    Test-Relay -CheckDeleteGuards
    Write-Host "[DONE] Worker update is live. No policies, lists, or list items were created, changed, or deleted by this script." -ForegroundColor Green
} catch {
    if ($deployed) {
        Write-Warning "Post-deploy verification failed. Attempting to restore the previous Worker version..."
        $rollbackResult = Invoke-NativeCommand { & npx wrangler rollback --config $ConfigFile --message "Automatic rollback: SentinelGate relay verification failed" }
        $rollbackResult.Output | ForEach-Object { Write-Host $_ }
        if ($rollbackResult.ExitCode -eq 0) {
            try {
                Test-Relay -CheckDeleteGuards
                Write-Host "[ROLLBACK OK] Previous Worker version is active and passed relay checks." -ForegroundColor Yellow
            } catch {
                Write-Error "Rollback command completed, but health checks still fail. Check the Worker deployment in Cloudflare Dashboard."
            }
        } else {
            Write-Error "Automatic rollback command failed. Use Cloudflare Dashboard → Workers & Pages → sentinelgate-relay → Deployments to roll back to the prior version."
        }
    }
    throw
} finally {
    Pop-Location
}
