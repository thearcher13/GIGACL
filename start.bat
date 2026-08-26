@echo off
setlocal

rem GIGACL Windows launcher. Run from Explorer or Command Prompt.
rem
rem   start.bat                  http on 0.0.0.0:8000
rem   set PORT=8080 ^&^& start.bat   a different port
rem   set PROXY=1 ^&^& start.bat     behind IIS/nginx: trust the forwarded client IP

set "PROJECT_DIR=%~dp0"
set "VENV_PYTHON=%PROJECT_DIR%venv\Scripts\python.exe"

if not defined HOST set "HOST=0.0.0.0"
if not defined PORT set "PORT=8000"

if /I "%~1"=="--help" goto :help

rem First run, or a checkout that has never been set up.
if not exist "%VENV_PYTHON%" (
    echo No virtual environment yet - running setup...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PROJECT_DIR%setup.ps1"
    if errorlevel 1 goto :setup_failed
)

rem A dependency added since the last install shows up here rather than as an
rem ImportError three screens into the boot log.
"%VENV_PYTHON%" -c "import uvicorn, fastapi, netmiko" >nul 2>&1
if errorlevel 1 (
    echo Installing missing dependencies...
    "%VENV_PYTHON%" -m pip install -r "%PROJECT_DIR%requirements.txt"
    if errorlevel 1 goto :install_failed
)

rem Behind a reverse proxy the address that connected to us is the proxy. The
rem app reads the peer address for the trusted-hosts check and for every audit
rem entry, so without this every user is recorded as 127.0.0.1. The allow-list
rem is what keeps it safe: the forwarded header is honoured only when the hop
rem we are talking to is the local proxy.
set "PROXY_ARGS="
if defined PROXY (
    if not defined FORWARDED_ALLOW_IPS set "FORWARDED_ALLOW_IPS=127.0.0.1"
    set "PROXY_ARGS=--proxy-headers --forwarded-allow-ips %FORWARDED_ALLOW_IPS%"
    echo Proxy mode is ON; client addresses come from the local reverse proxy.
)

rem Deliberately one worker. Live SSH sessions, the switch terminal's channels
rem and the per-user connection pool all live in this process's memory, and
rem SQLite takes one writer at a time.
echo.
echo Starting GIGACL on http://%HOST%:%PORT%
echo Press Ctrl+C to stop.
echo.

pushd "%PROJECT_DIR%backend"
"%VENV_PYTHON%" -m uvicorn main:app --host "%HOST%" --port "%PORT%" --workers 1 %PROXY_ARGS%
set "EXIT_CODE=%ERRORLEVEL%"
popd
exit /b %EXIT_CODE%

:help
echo Usage: start.bat
echo.
echo Optional environment variables:
echo   HOST                  Bind address ^(default: 0.0.0.0^)
echo   PORT                  HTTP port    ^(default: 8000^)
echo   PROXY                 Set to 1 when running behind a reverse proxy
echo   FORWARDED_ALLOW_IPS   Proxy address to trust ^(default: 127.0.0.1^)
echo.
echo Example: set PORT=8080 ^&^& start.bat
exit /b 0

:setup_failed
echo.
echo ERROR: Setup did not complete. Run it by hand to see the full output:
echo   powershell -ExecutionPolicy Bypass -File "%PROJECT_DIR%setup.ps1"
call :hold
exit /b 1

:install_failed
echo.
echo ERROR: Could not install the project dependencies.
call :hold
exit /b 1

rem Launched from Explorer the console closes the instant this script ends, so
rem an error message would never be read. CMDCMDLINE carries the /c that
rem Explorer adds; from an existing prompt it does not, and we skip the pause.
:hold
echo %CMDCMDLINE% | find /i " /c" >nul && pause
exit /b 0
