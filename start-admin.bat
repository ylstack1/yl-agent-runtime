@echo off
rem YL Agent Runtime — Admin Web Console Starter
rem One-click: creates config if missing, starts the server, opens the admin GUI.
rem No TOML editing, no cargo, no developer steps required.

setlocal

set YL_EXE=%~dp0target\debug\yl.exe
set DATA_DIR=%LOCALAPPDATA%\yl-agent-runtime\data
set CONFIG_FILE=%LOCALAPPDATA%\yl-agent-runtime\runtime.toml
set PORT=8081

echo [YL Admin] Checking for server binary...
if not exist "%YL_EXE%" (
    echo [YL Admin] ERROR: %YL_EXE% not found. Build first: cargo build -p runtime-cli
    pause
    exit /b 1
)

echo [YL Admin] Ensuring config exists at %CONFIG_FILE%
if not exist "%CONFIG_FILE%" (
    mkdir "%LOCALAPPDATA%\yl-agent-runtime" >nul 2>&1
    echo Creating default config...
    call :write_config "%CONFIG_FILE%"
)

echo [YL Admin] Starting server on port %PORT%...
set YL_RUNTIME_CONFIG=%CONFIG_FILE%
start "" "%YL_EXE%" serve --allow-remote --port %PORT%

echo [YL Admin] Waiting for server to start...
set /a tries=0
:wait
curl.exe -s -o nul -w "%{http_code}" http://127.0.0.1:%PORT%/health 2>nul | findstr "200" >nul
if %errorlevel% equ 0 goto started
set /a tries+=1
if %tries% geq 30 goto timeout
timeout /t 1 >nul
goto wait

:started
echo [YL Admin] Server is running at http://127.0.0.1:%PORT%
echo [YL Admin] Opening admin console...
start "" "http://127.0.0.1:%PORT%/ui"
echo [YL Admin] Admin console opened. Close this window to stop the server.
goto end

:timeout
echo [YL Admin] ERROR: Server did not start in time.
pause
goto end

:write_config
echo version = "0.1.0" > "%1"
echo data_dir = "%DATA_DIR%" >> "%1"
echo config_dir = "%LOCALAPPDATA%\yl-agent-runtime\config" >> "%1"
echo log_dir = "%LOCALAPPDATA%\yl-agent-runtime\logs" >> "%1"
echo cache_dir = "%LOCALAPPDATA%\yl-agent-runtime\cache" >> "%1"
echo. >> "%1"
echo [daemon] >> "%1"
echo bind_address = "127.0.0.1" >> "%1"
echo port = 0 >> "%1"
echo idle_timeout_seconds = 3600 >> "%1"
echo max_sessions = 100 >> "%1"
echo startup_timeout_seconds = 5 >> "%1"
echo. >> "%1"
echo [policy] >> "%1"
echo default_profile = "development" >> "%1"
echo policy_dir = "%LOCALAPPDATA%\yl-agent-runtime\config\policies" >> "%1"
echo fail_closed = true >> "%1"
echo require_approval_for = [] >> "%1"
echo approval_ttl_seconds = 1800 >> "%1"
echo yolo = false >> "%1"
echo. >> "%1"
echo [audit] >> "%1"
echo enabled = true >> "%1"
echo retention_days = 90 >> "%1"
echo max_log_size_mb = 100 >> "%1"
echo export_format = "jsonl" >> "%1"
echo redact_secrets = true >> "%1"
echo. >> "%1"
echo [backend] >> "%1"
echo preferred_backend = "native" >> "%1"
echo enable_native = true >> "%1"
echo enable_windows_sandbox = true >> "%1"
echo enable_linux_sandbox = true >> "%1"
echo enable_macos_sandbox = true >> "%1"
echo enable_arapuca = false >> "%1"
echo enable_virtx = false >> "%1"
echo. >> "%1"
echo [transport] >> "%1"
echo enable_stdio = true >> "%1"
echo enable_streamable_http = false >> "%1"
echo http_bind_address = "127.0.0.1" >> "%1"
echo http_port = 0 >> "%1"
echo enable_iroh = false >> "%1"
echo. >> "%1"
echo [remote] >> "%1"
echo enabled = true >> "%1"
echo pairing_required = false >> "%1"
echo session_timeout_seconds = 1800 >> "%1"
echo rate_limit_per_minute = 100 >> "%1"
echo max_request_size_mb = 10 >> "%1"
echo. >> "%1"
echo [workspace] >> "%1"
echo roots = [] >> "%1"
echo read_only_roots = [] >> "%1"
echo max_file_size = 10485760 >> "%1"
echo. >> "%1"
echo [discovery] >> "%1"
echo enabled = true >> "%1"
echo default_root_id = "" >> "%1"
echo show_hidden = false >> "%1"
echo follow_symlinks = false >> "%1"
echo max_depth = 12 >> "%1"
echo max_entries_per_page = 250 >> "%1"
goto :eof

:end
endlocal
