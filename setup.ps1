# GIGACL - one-time setup for Windows.
#
# Creates the virtual environment, installs the pinned dependencies, and
# prepares .env. Safe to re-run: it upgrades an existing install in place and
# never overwrites an existing .env, because that file holds the key the stored
# switch passwords are encrypted with.
#
# Run from PowerShell in the project folder:
#   powershell -ExecutionPolicy Bypass -File .\setup.ps1

$ErrorActionPreference = 'Stop'

$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Venv       = Join-Path $ProjectDir 'venv'
$VenvPython = Join-Path $Venv 'Scripts\python.exe'

function Fail($message) { Write-Host "ERROR: $message" -ForegroundColor Red; exit 1 }

# ---- Python ---------------------------------------------------------------
# The py launcher ships with the python.org installer and is the reliable way
# to ask for a specific version; plain `python` on Windows may be the Microsoft
# Store stub, which is not a working interpreter.
$python = $null
if (Get-Command py -ErrorAction SilentlyContinue) {
    foreach ($v in '3.13','3.12','3.11','3.10') {
        & py "-$v" -c "import sys" 2>$null
        if ($LASTEXITCODE -eq 0) { $python = @('py', "-$v"); break }
    }
}
if (-not $python -and (Get-Command python -ErrorAction SilentlyContinue)) {
    $ok = & python -c "import sys; raise SystemExit(0 if sys.version_info[:2] >= (3,10) else 1)" 2>$null
    if ($LASTEXITCODE -eq 0) { $python = @('python') }
}
if (-not $python) {
    Fail "Python 3.10 or newer was not found. Install it from https://www.python.org/downloads/windows/ and tick 'Add Python to PATH'."
}
Write-Host "Using $(& $python[0] $python[1..($python.Count-1)] -V)"

# ---- Virtual environment --------------------------------------------------
if (-not (Test-Path $VenvPython)) {
    Write-Host 'Creating the virtual environment...'
    & $python[0] $python[1..($python.Count-1)] -m venv $Venv
    if ($LASTEXITCODE -ne 0) { Fail 'Could not create the virtual environment.' }
}

Write-Host 'Installing dependencies...'
& $VenvPython -m pip install --quiet --upgrade pip
if ($LASTEXITCODE -ne 0) { Fail 'Could not upgrade pip.' }
& $VenvPython -m pip install --quiet -r (Join-Path $ProjectDir 'requirements.txt')
if ($LASTEXITCODE -ne 0) { Fail 'Could not install the dependencies.' }

# ---- Configuration --------------------------------------------------------
$envFile = Join-Path $ProjectDir '.env'
if (-not (Test-Path $envFile)) {
    Copy-Item (Join-Path $ProjectDir '.env.example') $envFile
    Write-Host 'Created .env from the example. The app fills in SECRET_KEY on first start.'
} else {
    Write-Host 'Keeping the existing .env.'
}

# The key in here decrypts every stored switch password: restrict it to the
# account that will run the service, plus Administrators.
try {
    $acl = Get-Acl $envFile
    $acl.SetAccessRuleProtection($true, $false)
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
    foreach ($who in @("$env:USERDOMAIN\$env:USERNAME", 'BUILTIN\Administrators')) {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $who, 'FullControl', 'Allow'))) | Out-Null
    }
    Set-Acl $envFile $acl
} catch {
    Write-Host "Note: could not tighten permissions on .env ($_). Restrict it by hand." -ForegroundColor Yellow
}

Write-Host ''
Write-Host 'Setup complete. Start the server with:'
Write-Host '  .\start.bat'
Write-Host ''
Write-Host "Then sign in at http://localhost:8000 as 'admin' with the password 'admin'"
Write-Host 'and change it immediately.'
