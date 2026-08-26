@echo off
setlocal

rem Stop the GIGACL Uvicorn server started by start.bat.
if not defined PORT set "PORT=8000"

echo Looking for GIGACL on port %PORT%...

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
  "$portNumber = [int]$env:PORT;" ^
  "$listeners = @(Get-NetTCPConnection -LocalPort $portNumber -State Listen -ErrorAction SilentlyContinue);" ^
  "if ($listeners.Count -eq 0) { Write-Host ('No server is listening on port ' + $portNumber + '.'); exit 2 };" ^
  "$stopped = $false;" ^
  "foreach ($processId in @($listeners.OwningProcess | Select-Object -Unique)) {" ^
  "  $process = Get-CimInstance Win32_Process -Filter ('ProcessId=' + $processId) -ErrorAction SilentlyContinue;" ^
  "  if ($process -and $process.CommandLine -match '(?i)(uvicorn\s+main:app|uvicorn\.main.*main:app)') {" ^
  "    Stop-Process -Id $processId -Force -ErrorAction Stop;" ^
  "    Write-Host ('Stopped GIGACL server (PID ' + $processId + ') on port ' + $portNumber + '.');" ^
  "    $stopped = $true;" ^
  "  }" ^
  "};" ^
  "if (-not $stopped) { Write-Error ('Port ' + $portNumber + ' is in use, but not by the GIGACL Uvicorn server. Nothing was stopped.'); exit 3 }"

set "EXIT_CODE=%ERRORLEVEL%"
if "%EXIT_CODE%"=="2" exit /b 0
exit /b %EXIT_CODE%
