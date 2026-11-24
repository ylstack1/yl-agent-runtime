@echo off
rem ================================================================================
rem YL Agent Runtime — Start/Restart Script
rem Run this from the project root directory
rem ================================================================================

setlocal enabledelayedexpansion

set PORT=8077
set EXE=target\debug\yl.exe

echo ================================================================================
echo YL Agent Runtime — Start Script
echo ================================================================================

rem Check if the binary exists
if not exist "%EXE%" (
    echo ERROR: Server binary not found at "%EXE%"
    echo        Run: cargo build -p runtime-cli
    pause
    exit /b 1
)

echo [INFO] Server binary found: %EXE%

rem Check if already running on port 8077
echo [INFO] Checking if server is already running on port %PORT%...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":%PORT%"') do (
    set PID=%%a
)

if defined PID (
    echo [INFO] Server already running with PID %PID%. Stopping it...
    taskkill /F /PID %PID% >nul 2>&1
    if %errorlevel% equ 0 (
        echo [INFO] Stopped old server (PID %PID%).
    ) else (
        echo [WARN] Could not stop PID %PID%. Trying again...
        timeout /t 2 /nobreak >nul
        taskkill /F /PID %PID% >nul 2>&1
    )
) else (
    echo [INFO] No server currently running on port %PORT%.
)

echo [INFO] Starting YL Agent Runtime on port %PORT%...
echo [INFO] Access web console at: http://127.0.0.1:%PORT%/ui
echo [INFO] Access LAN (phone/Android): http://<YOUR_IP>:%PORT%/ui
echo ================================================================================

rem Start the server in background
start "YL Agent Runtime" "%EXE%" serve --allow-remote --insecure-http --port %PORT% --root .

echo [INFO] Server started. Waiting for it to be ready...

:wait
timeout /t 1 /nobreak >nul
powershell -Command "try { \$r = Invoke-RestMethod -Uri 'http://127.0.0.1:%PORT%/health' -ErrorAction Stop; Write-Host \$r.status } catch { }" | findstr "ok" >nul
if %errorlevel% equ 0 (
    echo [SUCCESS] Server is running on port %PORT%!
    echo [INFO] Web console: http://127.0.0.1:%PORT%/ui
    echo [INFO] LAN access:   http://<YOUR_IP>:%PORT%/ui (TLS if enabled)
    echo [INFO] Bearer token:   Run 'yl pairing request' then 'yl pairing approve <code>' then 'yl pairing authenticate <device_id> --key-hex <key>'
    echo ================================================================================
    goto end
)

echo [WARNING] Server did not respond within 15 seconds. Check logs:
echo         target\debug\yl.exe output above
echo [INFO] You can still try: http://127.0.0.1:%PORT%/ui

:end
echo Done.
pause