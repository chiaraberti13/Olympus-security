<# 
VULNERABILITY ASSESSMENT PLATFORM - WINDOWS INSTALLER
Provides a best-effort setup for Windows using PowerShell.
Requires PowerShell 5+ and internet access for dependency downloads.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -----------------------------------------------------------------------------
# Logging helpers
# -----------------------------------------------------------------------------
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile = "installer_$Timestamp.log"

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet("INFO","SUCCESS","WARN","ERROR")][string]$Level = "INFO"
    )
    $prefix = switch ($Level) {
        "INFO" { "[INFO]" }
        "SUCCESS" { "[+]" }
        "WARN" { "[!]" }
        "ERROR" { "[X]" }
    }
    $line = "{0} {1}" -f $prefix, $Message
    Write-Host $line
    Add-Content -Path $LogFile -Value ("[{0}] {1}" -f (Get-Date -Format "s"), $line)
}

function Handle-Error {
    param([string]$Context)
    Write-Log "Installation failed: $Context" "ERROR"
    Write-Log "Check the log file for details: $LogFile" "ERROR"
    exit 1
}

# -----------------------------------------------------------------------------
# Validation helpers
# -----------------------------------------------------------------------------
function Test-RequiredFiles {
    Write-Log "Validating required project files..."
    $requiredFiles = @(
        "app.py",
        "config.py",
        "database.py",
        "scanner_engine.py",
        "report_generator.py",
        "requirements.txt",
        "scanners/__init__.py",
        "scanners/nuclei_scanner.py",
        "scanners/nmap_scanner.py",
        "scanners/whatweb_scanner.py",
        "scanners/subfinder_scanner.py",
        "scanners/nikto_scanner.py",
        "templates/index.html",
        "templates/scan_detail.html",
        "templates/scans_list.html"
    )

    $missing = @()
    foreach ($file in $requiredFiles) {
        if (-not (Test-Path -Path $file)) {
            $missing += "$file (missing)"
        } elseif ((Get-Item -Path $file).Length -eq 0) {
            $missing += "$file (empty)"
        } else {
            Write-Log "File OK: $file" "SUCCESS"
        }
    }

    if ($missing.Count -gt 0) {
        Write-Log "Missing or incomplete files detected:" "ERROR"
        $missing | ForEach-Object { Write-Log " - $_" "ERROR" }
        throw "Required files are missing or incomplete."
    }
}

function Assert-PythonVersion {
    param([string]$PythonCommand = "python")
    Write-Log "Checking Python version..."
    $versionOutput = & $PythonCommand -c @"
import sys
min_v = (3, 10, 0)
max_v = (3, 12, 99)
current = sys.version_info[:3]
if current < min_v or current > max_v:
    print(
        f"Unsupported Python {current[0]}.{current[1]}.{current[2]} detected. "
        "Supported versions: 3.10.x - 3.12.x."
    )
    raise SystemExit(1)
print(f"Python {current[0]}.{current[1]}.{current[2]} detected (OK).")
"@

    if ($LASTEXITCODE -ne 0) {
        throw $versionOutput
    }

    Write-Log $versionOutput "SUCCESS"
}

# -----------------------------------------------------------------------------
# Dependency installers (best effort)
# -----------------------------------------------------------------------------
function Install-WithWinget {
    param([string]$Id, [string]$Name)
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Log "Installing $Name via winget..."
        winget install --id $Id --silent --accept-source-agreements --accept-package-agreements
        Write-Log "$Name installed" "SUCCESS"
    } else {
        Write-Log "winget not found. Please install $Name manually." "WARN"
    }
}

function Ensure-Command {
    param([string]$Command, [string]$Name, [string]$WingetId)
    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
        Write-Log "$Name not found." "WARN"
        if ($WingetId) {
            Install-WithWinget -Id $WingetId -Name $Name
        }
    } else {
        Write-Log "$Name already available." "SUCCESS"
    }
}

# -----------------------------------------------------------------------------
# Main execution
# -----------------------------------------------------------------------------
try {
    Write-Log "Starting Windows installation..."

    Test-RequiredFiles

    # Ensure core tools (prefer Python 3.12 to match Linux/macOS installer)
    Ensure-Command -Command "python" -Name "Python 3" -WingetId "Python.Python.3.12"
    Ensure-Command -Command "git" -Name "Git" -WingetId "Git.Git"
    Ensure-Command -Command "go" -Name "Go" -WingetId "GoLang.Go"

    Assert-PythonVersion -PythonCommand "python"

    # Optional security tools
    Ensure-Command -Command "nmap" -Name "Nmap" -WingetId "Insecure.Nmap"
    Ensure-Command -Command "nikto" -Name "Nikto" -WingetId ""
    Ensure-Command -Command "whatweb" -Name "WhatWeb" -WingetId ""

    # Redis is required for Celery (async scans). It is not available via winget.
    # Options:
    #   1. Install Redis for Windows: https://github.com/microsoftarchive/redis/releases
    #   2. Use WSL2 + Ubuntu and run: sudo apt install redis
    #   3. Use Docker: docker run -d -p 6379:6379 redis:7
    if (-not (Get-Command redis-cli -ErrorAction SilentlyContinue)) {
        Write-Log "Redis is NOT installed. Celery (async scanning) requires Redis." "WARN"
        Write-Log "Install options:" "WARN"
        Write-Log "  - WSL2 + Ubuntu: sudo apt install redis  (recommended)" "WARN"
        Write-Log "  - Docker:        docker run -d -p 6379:6379 redis:7" "WARN"
        Write-Log "  - Windows port:  https://github.com/microsoftarchive/redis/releases" "WARN"
    } else {
        Write-Log "Redis available." "SUCCESS"
    }

    # Configure Go environment for Go-installed tools
    if (-not $env:GOPATH) {
        $env:GOPATH = Join-Path $HOME "go"
        $env:Path = "$env:Path;$env:GOPATH\bin"
        Write-Log "Configured GOPATH at $env:GOPATH" "SUCCESS"
    }

    # Install Go-based tools (best effort)
    if (Get-Command go -ErrorAction SilentlyContinue) {
        $goVersionText = (go version)
        $goVersion = $goVersionText -replace "go version go", "" -replace "\s.*", ""
        $goParts = $goVersion.Split(".")
        $major = [int]$goParts[0]
        $minor = [int]$goParts[1]
        if ($major -lt 1 -or ($major -eq 1 -and $minor -lt 19)) {
            Write-Log "Go $goVersion rilevato. Nuclei v3 richiede Go >= 1.19." "WARN"
            Write-Log "Aggiorna Go da https://go.dev/dl/ e riprova l'installazione." "WARN"
        } else {
            Write-Log "Installing Go-based security tools..."
            go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
            go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
            go install github.com/tomnomnom/assetfinder@latest
            Write-Log "Go-based tools installed" "SUCCESS"
        }
    } else {
        Write-Log "Go not available. Skipping Go-based tools." "WARN"
    }

    # Create virtual environment
    if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
        throw "Python is required but was not found after installation attempts."
    }

    Write-Log "Creating Python virtual environment..."
    python -m venv venv
    $venvPython = Join-Path $PWD "venv\Scripts\python.exe"

    Write-Log "Upgrading pip..."
    & $venvPython -m pip install --upgrade pip setuptools wheel

    Write-Log "Installing Python dependencies..."
    & $venvPython -m pip install -r requirements.txt

    Write-Log "Initializing database..."
    & $venvPython -c "from database import init_db; init_db()"

    # -----------------------------------------------------------------------------
    # Verification
    # -----------------------------------------------------------------------------
    Write-Log "Verifying Python dependencies..."
    $verifyScript = @"
import sys
packages = ['fastapi', 'uvicorn', 'reportlab', 'sqlalchemy', 'celery']
errors = 0
for pkg in packages:
    try:
        __import__(pkg)
        print(f'[+] {pkg}: OK')
    except ImportError:
        print(f'[X] {pkg}: NOT FOUND')
        errors += 1
sys.exit(errors)
"@
    $verifyResult = & $venvPython -c $verifyScript
    $verifyResult | ForEach-Object { Write-Log $_ }
    if ($LASTEXITCODE -ne 0) {
        Write-Log "Some Python packages are missing. Review errors above." "WARN"
    }

    Write-Log "Verifying external tools..."
    $tools = @("nmap", "nuclei", "subfinder", "git")
    foreach ($tool in $tools) {
        if (Get-Command $tool -ErrorAction SilentlyContinue) {
            Write-Log "$tool`: OK" "SUCCESS"
        } else {
            Write-Log "$tool`: NOT FOUND (optional — scanner will run in simulated mode)" "WARN"
        }
    }

    Write-Log "" "INFO"
    Write-Log "=== INSTALLATION COMPLETE ===" "SUCCESS"
    Write-Log "Next steps:" "INFO"
    Write-Log "  1. Activate the virtual environment:  .\venv\Scripts\Activate.ps1" "INFO"
    Write-Log "  2. Copy and edit configuration:       copy .env.example .env" "INFO"
    Write-Log "  3. Start Redis (see warning above if missing)" "INFO"
    Write-Log "  4. Start the server:                  python app.py" "INFO"
    Write-Log "  5. Open the dashboard:                http://localhost:8000" "INFO"
} catch {
    Handle-Error $_.Exception.Message
}
