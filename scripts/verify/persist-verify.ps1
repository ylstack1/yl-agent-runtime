# YL Agent Runtime — Stage 1 persistence verification (PowerShell)
# Verifies that pairings, devices, sessions and audit state survive a server
# restart (persisted to data_dir/*.jsonl).
#
# Loopback URL from YL_RUNTIME_URL (default http://127.0.0.1:8077).
# Server config from YL_RUNTIME_CONFIG (default stage-1 temp config).
#
# Usage:
#   $env:YL_RUNTIME_URL="http://127.0.0.1:8081"
#   $env:YL_RUNTIME_CONFIG="C:\...\verify-cfg\runtime.toml"
#   $env:YL_RUNTIME_DATA_DIR="C:\...\verify-cfg\data"
#   ./scripts/verify/persist-verify.ps1

$ErrorActionPreference = 'Continue'

$baseUrl = if ($env:YL_RUNTIME_URL) { $env:YL_RUNTIME_URL } else { 'http://127.0.0.1:8077' }
$baseUrl = $baseUrl.TrimEnd('/')
$config  = if ($env:YL_RUNTIME_CONFIG) { $env:YL_RUNTIME_CONFIG } else { 'C:\Users\SawYeLin\AppData\Local\Temp\opencode\stage1-cfg\runtime.toml' }
$yl      = 'target\debug\yl.exe'

$dataDir = if ($env:YL_RUNTIME_DATA_DIR) { $env:YL_RUNTIME_DATA_DIR } else { 'C:\Users\SawYeLin\AppData\Local\Temp\opencode\stage1-cfg\data' }
$identityLog = Join-Path $dataDir 'identity.jsonl'
$servePort = [Uri]$baseUrl | Select-Object -ExpandProperty Port
$lanUrl = if ($env:YL_LAN_URL) { $env:YL_LAN_URL.TrimEnd('/') } else { "https://192.168.1.130:$servePort" }

# Make the yl CLI subcommands (pairing/devices) talk to the same base URL.
$env:YL_RUNTIME_URL = $baseUrl

$failures = 0
$passes   = 0

function Check($name, $ok, $detail) {
    if ($ok) {
        Write-Output ("PASS  {0}  {1}" -f $name, $detail)
        $script:passes++
    } else {
        Write-Output ("FAIL  {0}  {1}" -f $name, $detail)
        $script:failures++
    }
}

function Stop-Yl {
    $p = Get-NetTCPConnection -LocalPort $servePort -State Listen -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty OwningProcess -Unique
    if ($p) { Stop-Process -Id $p -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2 }
}

function Start-Yl {
    $env:YL_RUNTIME_CONFIG = $config
    $outLog = Join-Path $dataDir 'serve-persist.out'
    $errLog = Join-Path $dataDir 'serve-persist.err'
    $proc = Start-Process -FilePath $yl -ArgumentList @('serve','--allow-remote','--port',$servePort) `
        -RedirectStandardOutput $outLog -RedirectStandardError $errLog -WindowStyle Hidden -PassThru
    Start-Sleep -Seconds 5
    $proc
}

function Get-Api($path, $bearer) {
    $h = @{ 'Accept' = 'application/json, text/event-stream' }
    if ($bearer) { $h['Authorization'] = "Bearer $bearer" }
    try {
        $r = Invoke-WebRequest -Uri ("$baseUrl$path") -Method GET -Headers $h -UseBasicParsing
        return @{ status = [int]$r.StatusCode }
    } catch {
        $code = 0
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        return @{ status = $code }
    }
}

function Get-Lan($path, $bearer) {
    $curlArgs = @('-s', '-o', 'NUL', '-w', '%{http_code}')
    $curlArgs += '-X'; $curlArgs += 'GET'
    $curlArgs += '-H'; $curlArgs += 'Accept: application/json, text/event-stream'
    if ($bearer) { $curlArgs += '-H'; $curlArgs += "Authorization: Bearer $bearer" }
    $curlArgs += '-k'; $curlArgs += "$lanUrl$path"
    $raw = & curl.exe @curlArgs 2>$null
    $text = ($raw -join '').Trim()
    $m = [regex]::Match($text, '\b(\d{3})\b')
    $code = if ($m.Success) { [int]$m.Groups[1].Value } else { 0 }
    return @{ status = $code }
}

Write-Output ("== Persist verify (1) - pair, authenticate, revoke ==")

# Pair + authenticate
$out = (& $yl pairing request --name 'persist-device' 2>&1 | Out-String)
$code  = ([regex]::Match($out, 'Pairing code:\s*(\d{6})')).Groups[1].Value
$seed  = ([regex]::Match($out, 'Device private key \(keep secret\):\s*([0-9a-f]{64})')).Groups[1].Value
Check 'pairing request issued' ($code.Length -eq 6) ("code=" + $code)

$approve = (& $yl pairing approve $code 2>&1 | Out-String)
$deviceId = ([regex]::Match($approve, 'Device id:\s*([0-9a-f\-]{36})')).Groups[1].Value
Check 'host approved pairing' ($deviceId.Length -eq 36) ("device=" + $deviceId)

$auth = (& $yl pairing authenticate $deviceId --key-hex $seed 2>&1 | Out-String)
$token = ([regex]::Match($auth, 'Session token:\s*(\S+)')).Groups[1].Value
Check 'device authenticated' ($token.Length -eq 36) ("token=" + $token)

# Token works before restart
$r = Get-Api '/api/v1/device' $token
Check 'token works before restart' ($r.status -eq 200) ("status=" + $r.status)

# Revoke device -> token invalidated (remote peer runs validate_session)
$rev = (& $yl devices revoke $deviceId 2>&1 | Out-String)
$r = Get-Lan '/api/v1/device' $token
Check 'revoked token rejected before restart' ($r.status -eq 401) ("status=" + $r.status)

# identity.jsonl written
$logWritten = Test-Path $identityLog
Check 'identity.jsonl written' $logWritten ("path=" + $identityLog)

Write-Output ("== Persist verify (2) - restart server ==")
Stop-Yl
Start-Yl

Write-Output ("== Persist verify (3) - state after restart ==")

# Same token still rejected after restart (remote peer runs validate_session)
$r = Get-Lan '/api/v1/device' $token
Check 'revoked token still rejected after restart' ($r.status -eq 401) ("status=" + $r.status)

# Device still registered + revoked
$list = (& $yl devices list 2>&1 | Out-String)
Check 'device still registered after restart' ($list -match $deviceId) 'listed'
Check 'device still marked revoked after restart' ($list -match 'revoked') 'revoked'

# Approved pairing still recorded
$pairings = (& $yl pairing list 2>&1 | Out-String)
Check 'approved pairing still recorded' ($pairings -match 'approved') 'approved pairing present'

# identity.jsonl still present / has events
$logEvents = if (Test-Path $identityLog) { (Get-Content $identityLog).Length } else { 0 }
Check 'identity.jsonl has events' ($logEvents -gt 0) ("events=" + $logEvents)

Write-Output ""
$total = $passes + $failures
Write-Output ("{0} / {1} persist checks passed" -f $passes, $total)
if ($failures -eq 0) { Write-Output 'ALL PERSIST CHECKS PASSED'; exit 0 } else { Write-Output ("{0} CHECK(S) FAILED" -f $failures); exit 1 }
