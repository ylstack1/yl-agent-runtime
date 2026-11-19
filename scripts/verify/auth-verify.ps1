# YL Agent Runtime — Stage 1 auth verification (PowerShell)
#
# Verifies the pairing / session / approval flow end-to-end over HTTP.
#
# Loopback URL (pairing, devices, CLI ops) comes from YL_RUNTIME_URL,
# defaulting to http://127.0.0.1:8077. Remote auth-gate tests use HTTPS on the
# LAN IP (YL_LAN_URL, defaulting to https://192.168.1.130:<same port>) because
# loopback peers bypass the session gate by design (§7.4).
#
# Usage:
#   $env:YL_RUNTIME_URL="http://127.0.0.1:8081"
#   $env:YL_LAN_URL="https://192.168.1.130:8081"
#   ./scripts/verify/auth-verify.ps1

$ErrorActionPreference = 'Continue'

$baseUrl = if ($env:YL_RUNTIME_URL) { $env:YL_RUNTIME_URL } else { 'http://127.0.0.1:8077' }
$baseUrl = $baseUrl.TrimEnd('/')
$port = [Uri]$baseUrl | Select-Object -ExpandProperty Port
$lanUrl = if ($env:YL_LAN_URL) { $env:YL_LAN_URL.TrimEnd('/') } else { "https://192.168.1.130:$port" }
$yl = 'target\debug\yl.exe'
$mcpBody = '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

$failures = 0
$passes   = 0

$tmpBody = "$env:TEMP\yl-verify-mcp-body.json"
Set-Content -Path $tmpBody -Value $mcpBody -Encoding UTF8

function Check($name, $ok, $detail) {
    if ($ok) {
        Write-Output "PASS  $name  $detail"
        $script:passes++
    } else {
        Write-Output "FAIL  $name  $detail"
        $script:failures++
    }
}

function HttpCode($url, $method, $bearer) {
    $curlArgs = @('-s', '-o', 'NUL', '-w', '%{http_code}')
    $curlArgs += '-X'; $curlArgs += $method
    $curlArgs += '-H'; $curlArgs += 'Content-Type: application/json'
    $curlArgs += '-H'; $curlArgs += 'Accept: application/json, text/event-stream'
    if ($bearer) { $curlArgs += '-H'; $curlArgs += "Authorization: Bearer $bearer" }
    if ($method -eq 'POST') { $curlArgs += '--data-binary'; $curlArgs += "@$tmpBody" }
    $curlArgs += '-k'; $curlArgs += $url
    $raw = & curl.exe @curlArgs 2>$null
    $text = ($raw -join '').Trim()
    $m = [regex]::Match($text, '\b(\d{3})\b')
    if ($m.Success) { [int]$m.Groups[1].Value } else { 0 }
}

function Post-Lan($path, $bearer) {
    @{ status = (HttpCode "$lanUrl$path" 'POST' $bearer) }
}

function Get-Lan($path, $bearer) {
    @{ status = (HttpCode "$lanUrl$path" 'GET' $bearer) }
}

# ---- 1. unauth REMOTE /mcp is rejected (remote peer, auth gate applies) ----
$r = Post-Lan '/mcp' $null
Check 'unauth remote /mcp rejected' ($r.status -eq 401) "status=$($r.status)"

# ---- 2. pair request (loopback CLI; returns 6-digit code + seed) -----------
$out = (& $yl pairing request --name 'verify-phone' 2>&1 | Out-String)
$code  = ([regex]::Match($out, 'Pairing code:\s*(\d{6})')).Groups[1].Value
$seed  = ([regex]::Match($out, 'Device private key \(keep secret\):\s*([0-9a-f]{64})')).Groups[1].Value
Check 'pair request returns a 6-digit code' ($code.Length -eq 6) "code=$code"

# ---- 3. status while pending -----------------------------------------------
$status = (& $yl pairing status $code 2>&1 | Out-String) | ConvertFrom-Json
Check 'pending status before approval' ($status.state -eq 'pending') "state=$($status.state)"

# ---- 4. authenticate before approval must fail -----------------------------
$pre = & $yl pairing authenticate 'e1297674-2ab1-4996-a911-be87e895ee6a' --key-hex $seed 2>&1 | Out-String
Check 'authenticate before approval fails' ($pre -notmatch 'Session token:') 'rejected'

# ---- 5. host approve -------------------------------------------------------
$approve = (& $yl pairing approve $code 2>&1 | Out-String)
$deviceId = ([regex]::Match($approve, 'Device id:\s*([0-9a-f\-]{36})')).Groups[1].Value
Check 'host approve returns device id' ($deviceId.Length -eq 36) "device=$deviceId"

# ---- 6. status after approval ----------------------------------------------
$status2 = (& $yl pairing status $code 2>&1 | Out-String) | ConvertFrom-Json
Check 'approved status exposes device id' ($status2.state -eq 'approved' -and $status2.device_id -eq $deviceId) "state=$($status2.state)"

# ---- 7. authenticate and get token -----------------------------------------
$auth = (& $yl pairing authenticate $deviceId --key-hex $seed 2>&1 | Out-String)
$token = ([regex]::Match($auth, 'Session token:\s*(\S+)')).Groups[1].Value
Check 'authenticate issues a token' ($token.Length -eq 36) "token=$token"

# ---- 8. authed REMOTE /api/v1/device allowed -------------------------------
$r = Get-Lan '/api/v1/device' $token
Check 'authed remote /api/v1/device allowed' ($r.status -eq 200) "status=$($r.status)"

# ---- 9. host-only endpoints refuse a remote peer (even with a valid token) -
$r = Get-Lan '/api/v1/pairings' $token
Check 'remote /api/v1/pairings refused (host-only)' ($r.status -eq 403 -or $r.status -eq 0) "status=$($r.status) (0 = LAN unreachable, acceptable)"

# ---- 10. wrong signature rejected ------------------------------------------
$badSeed = ('11' * 32)
$bad = & $yl pairing authenticate $deviceId --key-hex $badSeed 2>&1 | Out-String
Check 'wrong key rejected' ($bad -notmatch 'Session token:') 'rejected'

# ---- 11. devices list shows paired device ----------------------------------
$dev = (& $yl devices list 2>&1 | Out-String)
Check 'devices list shows paired device' ($dev -match $deviceId) 'listed'

# ---- 12. revoke device invalidates the live remote token -------------------
$rev = (& $yl devices revoke $deviceId 2>&1 | Out-String)
$r = Post-Lan '/mcp' $token
Check 'revoked device token rejected' ($r.status -eq 401) "status=$($r.status)"

# ---- 13. re-authenticate after revoke must fail ----------------------------
$reauth = & $yl pairing authenticate $deviceId --key-hex $seed 2>&1 | Out-String
Check 're-authenticate after revoke rejected' ($reauth -notmatch 'Session token:') 'rejected'

Write-Output ""
$total = $passes + $failures
Write-Output "$passes / $total auth checks passed"
if ($failures -eq 0) { Write-Output "ALL AUTH CHECKS PASSED"; exit 0 } else { Write-Output "$failures CHECK(S) FAILED"; exit 1 }
