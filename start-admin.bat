@echo off
rem ===================================================================
rem  YL Agent Runtime - Admin Web Console
rem
rem  Double-click this file. It needs no TOML editing and no terminal
rem  commands: the runtime creates its own per-user config, starts the
rem  server and opens the admin console in your browser.
rem
rem  Everything else (workspace roots, projects, devices, approvals) is
rem  managed from that console or from `yl <command>` - never by hand.
rem ===================================================================
setlocal

set "ROOT=%~dp0"
set "EXE=%ROOT%target\release\yl.exe"
if exist "%EXE%" goto run

set "EXE=%ROOT%target\debug\yl.exe"
if exist "%EXE%" goto run

echo [YL Admin] The runtime binary was not found.
where cargo >nul 2>&1
if errorlevel 1 (
    echo [YL Admin] ERROR: yl.exe is missing and cargo is not installed.
    echo [YL Admin] Install Rust from https://rustup.rs or copy yl.exe to %ROOT%target\debug\
    pause
    exit /b 1
)

echo [YL Admin] First run: building the runtime ^(one time, may take a few minutes^)...
cargo build -p runtime-cli --manifest-path "%ROOT%Cargo.toml"
if errorlevel 1 (
    echo [YL Admin] ERROR: build failed. See the output above.
    pause
    exit /b 1
)
set "EXE=%ROOT%target\debug\yl.exe"
if not exist "%EXE%" (
    echo [YL Admin] ERROR: build finished but %EXE% is missing.
    pause
    exit /b 1
)

:run
"%EXE%" admin %*
echo.
echo [YL Admin] Runtime stopped.
pause
endlocal
