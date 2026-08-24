<#
.SYNOPSIS
    Argus automated installer for Windows (PowerShell).

.DESCRIPTION
    Idempotent installer that:
      1. Ensures Python 3.8+ is available (auto-installs via winget if missing).
      2. Creates an isolated virtual environment in .\.venv.
      3. Installs Argus and its dependencies into that venv.
      4. Creates a `argus.cmd` launcher in a user bin folder and adds it to PATH.

.PARAMETER WithDns
    Also install dnspython for real MX-record checks in the email module.

.PARAMETER Dev
    Also install dev/test tooling (pytest, ruff).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\install.ps1
    powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -WithDns
#>
[CmdletBinding()]
param(
    [switch]$WithDns,
    [switch]$Dev
)

$ErrorActionPreference = "Stop"

function Info($m)  { Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m)    { Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m)  { Write-Host "[!] $m" -ForegroundColor Yellow }
function Die($m)   { Write-Host "[x] $m" -ForegroundColor Red; exit 1 }

Write-Host "Argus installer (Windows)" -ForegroundColor White

$RepoDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$VenvDir = Join-Path $RepoDir ".venv"
$BinDir  = Join-Path $env:LOCALAPPDATA "Programs\Argus\bin"
Info "Repository: $RepoDir"

# --------------------------------------------------- ensure Python ----------
function Get-Python {
    foreach ($cand in @("python", "python3", "py -3")) {
        try {
            $parts = $cand.Split(" ")
            $ver = & $parts[0] $parts[1..($parts.Length-1)] --version 2>&1
            if ($LASTEXITCODE -eq 0 -and $ver -match "Python 3\.(\d+)") {
                if ([int]$Matches[1] -ge 8) { return $cand }
            }
        } catch { }
    }
    return $null
}

$Py = Get-Python
if (-not $Py) {
    Warn "Python 3.8+ not found."
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Info "Installing Python via winget…"
        winget install -e --id Python.Python.3.12 --accept-source-agreements --accept-package-agreements
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("Path","User")
        $Py = Get-Python
    }
    if (-not $Py) {
        Die "Could not install Python automatically. Install Python 3.8+ from https://python.org (check 'Add to PATH'), then re-run."
    }
}
Info "Using Python command: $Py"

# --------------------------------------------------- create venv ------------
Info "Creating virtual environment in .venv …"
$pyParts = $Py.Split(" ")
& $pyParts[0] $pyParts[1..($pyParts.Length-1)] -m venv $VenvDir
$VenvPy = Join-Path $VenvDir "Scripts\python.exe"
if (-not (Test-Path $VenvPy)) { Die "Virtual environment creation failed." }

& $VenvPy -m pip install --upgrade pip | Out-Null

# --------------------------------------------------- install package --------
Info "Installing Argus and dependencies …"
& $VenvPy -m pip install -e $RepoDir
if ($WithDns) { Info "Installing dnspython …"; & $VenvPy -m pip install "dnspython>=2.4.0" }
if ($Dev)     { Info "Installing dev tools …"; & $VenvPy -m pip install "pytest>=7.0" "pytest-mock>=3.10" "ruff>=0.1.0" }
Ok "Package installed into virtualenv."

# --------------------------------------------------- launcher ---------------
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
$Launcher = Join-Path $BinDir "argus.cmd"
@"
@echo off
"$VenvPy" -m argus %*
"@ | Set-Content -Path $Launcher -Encoding ASCII
Ok "Launcher installed: $Launcher"

# --------------------------------------------------- PATH -------------------
$userPath = [System.Environment]::GetEnvironmentVariable("Path","User")
if ($userPath -notlike "*$BinDir*") {
    [System.Environment]::SetEnvironmentVariable("Path", "$userPath;$BinDir", "User")
    Ok "Added $BinDir to your user PATH (open a new terminal to use it)."
} else {
    Info "PATH already contains the launcher directory."
}

Write-Host ""
Ok "Installation complete!"
Write-Host "  Run it with:          argus" -ForegroundColor Cyan
Write-Host "  One-off command:      argus ip 8.8.8.8" -ForegroundColor Cyan
Write-Host "  Without the launcher: `"$VenvPy`" -m argus" -ForegroundColor Cyan
