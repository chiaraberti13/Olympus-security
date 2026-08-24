#!/bin/bash

##############################################################################
# VULNERABILITY ASSESSMENT PLATFORM - AUTO INSTALLER
# Cross-platform installer for Linux (Ubuntu/Debian), macOS, and Windows.
# Author: DevSecOps Team
# Version: 2.0
##############################################################################

set -Eeuo pipefail  # Fail fast, catch errors in pipelines, and treat unset vars as errors.
IFS=$'\n\t'

# Ensure the installer runs from the repository root.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Output colors (ANSI). Use tput if available for better compatibility.
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Selected Python binary for the installer.
PYTHON_BIN=""
GO_TOO_OLD=0
MACOS_LEGACY=0
MACOS_VERSION=""
MACOS_MAJOR=""
MACOS_MINOR=""

# ASCII logo for the installer UI.
print_logo() {
    echo -e "${BLUE}"
    cat << "EOF"
╦  ╦┬ ┬┬  ┌┐┌  ╔═╗┌─┐┌─┐┌─┐┌─┐┌─┐┌┬┐┌─┐┌┐┌┌┬┐
╚╗╔╝│ ││  │││  ╠═╣└─┐└─┐├┤ └─┐└─┐│││├┤ │││ │ 
 ╚╝ └─┘┴─┘┘└┘  ╩ ╩└─┘└─┘└─┘└─┘└─┘┴ ┴└─┘┘└┘ ┴ 
    Professional Security Scanner Platform
EOF
    echo -e "${NC}"
}

# Logging helpers with consistent prefixes.
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
    log_error_to_file "$1"
}

# On macOS, proactively fix Ruby psych build issues often triggered by WhatWeb bundler deps.
ensure_psych_gem_for_whatweb() {
    if [ "$PLATFORM" != "macos" ]; then
        return 0
    fi

    if ! command -v gem &> /dev/null; then
        log_warning "RubyGems not found. Skipping psych preflight for WhatWeb."
        return 0
    fi

    if gem list -i psych -v 5.3.1 &> /dev/null; then
        log_success "psych 5.3.1 already available for Ruby."
        return 0
    fi

    log_info "Preflighting Ruby psych 5.3.1 for WhatWeb..."
    local libyaml_prefix=""
    if command -v brew &> /dev/null; then
        libyaml_prefix="$(brew --prefix libyaml 2>/dev/null || true)"
        if [ -n "$libyaml_prefix" ]; then
            export CPPFLAGS="-I${libyaml_prefix}/include ${CPPFLAGS:-}"
            export LDFLAGS="-L${libyaml_prefix}/lib ${LDFLAGS:-}"
            export PKG_CONFIG_PATH="${libyaml_prefix}/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
        fi
    fi

    if gem install psych -v '5.3.1' --source 'https://rubygems.org/'; then
        log_success "psych 5.3.1 installed successfully."
    else
        log_warning "psych 5.3.1 install failed. WhatWeb install may fallback to local wrapper."
    fi
}

# Path for installer logs to support error analysis.
# Use absolute paths so logs land in the repo root even when the CWD changes
# (e.g. after pushd inside install_security_tools).
_LOG_TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${SCRIPT_DIR}/installer_${_LOG_TIMESTAMP}.log"
ERROR_LOG_FILE="${SCRIPT_DIR}/installer_errors_${_LOG_TIMESTAMP}.log"

# Log to file as well to make troubleshooting easier.
log_to_file() {
    echo "[$(date +%Y-%m-%dT%H:%M:%S%z)] $1" >> "$LOG_FILE"
}

# Log only errors to the error-only log file.
log_error_to_file() {
    echo "[$(date +%Y-%m-%dT%H:%M:%S%z)] ERROR: $1" >> "$ERROR_LOG_FILE"
}

# Ensure ~/.local/bin is in PATH and persisted for future shells.
ensure_local_bin_path() {
    if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
        export PATH="$HOME/.local/bin:$PATH"
        if [ -f "$HOME/.bashrc" ]; then
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
        fi
        if [ -f "$HOME/.zshrc" ]; then
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.zshrc"
        fi
    fi
}

# Ensure /usr/local/go/bin is available in PATH for Go installs from official tarballs.
ensure_go_path() {
    if [[ ":$PATH:" != *":/usr/local/go/bin:"* ]]; then
        export PATH="/usr/local/go/bin:$PATH"
        if [ -f "$HOME/.bashrc" ]; then
            echo 'export PATH="/usr/local/go/bin:$PATH"' >> "$HOME/.bashrc"
        fi
        if [ -f "$HOME/.zshrc" ]; then
            echo 'export PATH="/usr/local/go/bin:$PATH"' >> "$HOME/.zshrc"
        fi
    fi
}

# Check if script is run as root to avoid permission mistakes.
check_root() {
    if [ "$EUID" -eq 0 ]; then 
        log_warning "Do not run this script as root. We will use sudo when needed."
        exit 1
    fi
}

# Detect OS and distribution to drive dependency installation.
detect_platform() {
    log_info "Detecting operating system..."

    OS_NAME="$(uname -s)"
    case "$OS_NAME" in
        Linux*)
            PLATFORM="linux"
            if [ -f /etc/os-release ]; then
                . /etc/os-release
                DISTRO="${ID:-unknown}"
                VERSION="${VERSION_ID:-unknown}"
                log_success "Detected Linux distribution: ${NAME:-$DISTRO} ${VERSION}"
            else
                log_error "Unable to detect Linux distribution (/etc/os-release missing)."
                exit 1
            fi
            ;;
        Darwin*)
            PLATFORM="macos"
            log_success "Detected macOS."
            ;;
        CYGWIN*|MINGW*|MSYS*)
            PLATFORM="windows"
            log_success "Detected Windows (Git Bash/Cygwin/MSYS)."
            ;;
        *)
            log_error "Unsupported OS: $OS_NAME"
            exit 1
            ;;
    esac
}

# Validate minimum macOS version for Homebrew support.
check_macos_version_support() {
    if [ "$PLATFORM" != "macos" ]; then
        return 0
    fi

    if ! command -v sw_vers &> /dev/null; then
        log_warning "Unable to determine macOS version (sw_vers missing)."
        log_warning "Proceeding without macOS version validation."
        return 0
    fi

    MACOS_VERSION="$(sw_vers -productVersion)"
    local major="${MACOS_VERSION%%.*}"
    local rest="${MACOS_VERSION#*.}"
    local minor="${rest%%.*}"

    if ! [[ "$major" =~ ^[0-9]+$ ]]; then
        log_warning "Unexpected macOS version format: ${MACOS_VERSION}. Proceeding anyway."
        return 0
    fi

    if ! [[ "$minor" =~ ^[0-9]+$ ]]; then
        minor="0"
    fi

    MACOS_MAJOR="$major"
    MACOS_MINOR="$minor"

    if (( major < 11 )); then
        log_error "macOS ${MACOS_VERSION} detected. This installer supports macOS 11+."
        log_error "Upgrade macOS or use a supported environment."
        exit 1
    fi

    if (( major < 13 )); then
        MACOS_LEGACY=1
        log_warning "macOS ${MACOS_VERSION} detected. Homebrew support may be limited."
        log_warning "If Homebrew fails, the installer will attempt to use MacPorts."
    fi
}

# Validate Python runtime version to prevent unsupported builds (e.g., pydantic-core).
check_python_version() {
    log_info "Checking Python version..."

    local candidates=("python3.12" "python3.11" "python3.10" "python3")
    local version_output=""
    local last_error=""

    for candidate in "${candidates[@]}"; do
        if ! command -v "$candidate" &> /dev/null; then
            continue
        fi

        if version_output=$("$candidate" << 'PY'
import sys
min_v = (3, 10, 0)
max_v = (3, 12, 99)
current = sys.version_info[:3]
if current < min_v or current > max_v:
    print(
        f"Unsupported Python {current[0]}.{current[1]}.{current[2]} detected. "
        "Supported versions: 3.10.x - 3.12.x."
    )
    sys.exit(1)
print(f"Python {current[0]}.{current[1]}.{current[2]} detected (OK).")
PY
); then
            PYTHON_BIN="$candidate"
            log_success "${version_output} (using ${PYTHON_BIN})"
            return 0
        else
            last_error="$version_output"
        fi
    done

    if [ -z "$last_error" ]; then
        log_error "python3 not found. Install Python 3.10-3.12 and re-run the installer."
        exit 1
    fi

    log_error "$last_error"
    log_error "Install Python 3.10-3.12 or ensure python3.12/3.11/3.10 is on your PATH."
    exit 1
}

# Validate required project files and detect incomplete/empty files early.
check_required_files() {
    log_info "Validating required project files..."
    local required_files=(
        "app.py"
        "config.py"
        "database.py"
        "scanner_engine.py"
        "report_generator.py"
        "requirements.txt"
        "scanners/__init__.py"
        "scanners/nuclei_scanner.py"
        "scanners/nmap_scanner.py"
        "scanners/whatweb_scanner.py"
        "scanners/subfinder_scanner.py"
        "scanners/nikto_scanner.py"
        "templates/index.html"
        "templates/scan_detail.html"
        "templates/scans_list.html"
    )

    local missing=0
    for file in "${required_files[@]}"; do
        if [ ! -f "$file" ]; then
            log_error "Missing required file: $file"
            log_to_file "Missing required file: $file"
            ((missing++))
        elif [ ! -s "$file" ]; then
            log_error "Incomplete file detected (empty): $file"
            log_to_file "Incomplete file detected (empty): $file"
            ((missing++))
        else
            log_success "File OK: $file"
        fi
    done

    if [ "$missing" -ne 0 ]; then
        log_error "One or more required files are missing or incomplete."
        log_error "Restore the project files and re-run the installer."
        exit 1
    fi
}

# Install system dependencies based on platform.
install_system_dependencies() {
    log_info "Installing system dependencies..."

    case "$PLATFORM" in
        linux)
            case "$DISTRO" in
                ubuntu|debian|kali|linuxmint|pop)
                    log_info "Updating apt repositories..."
                    sudo apt-get update -qq

                    log_info "Installing base packages..."
                    sudo apt-get install -y \
                        python3 \
                        python3-pip \
                        python3-venv \
                        git \
                        wget \
                        curl \
                        nmap \
                        nikto \
                        golang-go \
                        build-essential \
                        libssl-dev \
                        libffi-dev \
                        libcairo2-dev \
                        libgdk-pixbuf2.0-dev \
                        libpango1.0-dev \
                        python3-dev \
                        sqlite3 \
                        libsqlite3-dev
                    ;;
                fedora)
                    log_info "Installing base packages via dnf (Fedora)..."
                    sudo dnf install -y \
                        python3 \
                        python3-pip \
                        git \
                        wget \
                        curl \
                        nmap \
                        nikto \
                        golang \
                        gcc \
                        openssl-devel \
                        libffi-devel \
                        cairo-devel \
                        gdk-pixbuf2-devel \
                        pango-devel \
                        python3-devel \
                        sqlite \
                        sqlite-devel
                    ;;
                centos|rhel|rocky|almalinux)
                    log_info "Installing base packages via dnf/yum (RHEL/CentOS/Rocky)..."
                    if command -v dnf &> /dev/null; then
                        sudo dnf install -y epel-release 2>/dev/null || true
                        sudo dnf install -y \
                            python3 \
                            python3-pip \
                            git \
                            wget \
                            curl \
                            nmap \
                            golang \
                            gcc \
                            openssl-devel \
                            libffi-devel \
                            cairo-devel \
                            gdk-pixbuf2-devel \
                            pango-devel \
                            python3-devel \
                            sqlite \
                            sqlite-devel
                    else
                        sudo yum install -y epel-release 2>/dev/null || true
                        sudo yum install -y \
                            python3 \
                            python3-pip \
                            git \
                            wget \
                            curl \
                            nmap \
                            golang \
                            gcc \
                            openssl-devel \
                            libffi-devel \
                            cairo-devel \
                            gdk-pixbuf2-devel \
                            pango-devel \
                            python3-devel \
                            sqlite \
                            sqlite-devel
                    fi
                    log_warning "nikto is not available in standard RHEL/CentOS repos. Install manually from https://cirt.net/Nikto2."
                    ;;
                arch|manjaro|endeavouros)
                    log_info "Installing base packages via pacman (Arch-based)..."
                    sudo pacman -Sy --noconfirm \
                        python \
                        python-pip \
                        git \
                        wget \
                        curl \
                        nmap \
                        nikto \
                        go \
                        base-devel \
                        cairo \
                        gdk-pixbuf2 \
                        pango \
                        sqlite
                    ;;
                opensuse*|sles)
                    log_info "Installing base packages via zypper (openSUSE/SLES)..."
                    sudo zypper install -y \
                        python3 \
                        python3-pip \
                        git \
                        wget \
                        curl \
                        nmap \
                        nikto \
                        go \
                        gcc \
                        libopenssl-devel \
                        libffi-devel \
                        cairo-devel \
                        gdk-pixbuf-devel \
                        pango-devel \
                        python3-devel \
                        sqlite3 \
                        sqlite3-devel
                    ;;
                *)
                    log_warning "Unsupported Linux distribution: $DISTRO"
                    log_warning "Automatic package installation skipped."
                    log_warning "Install manually: python3, python3-pip, python3-venv, git, curl, nmap, nikto, go, gcc, libssl-dev, sqlite3"
                    log_warning "Then re-run this installer."
                    ;;
            esac
            ;;
        macos)
            check_macos_version_support
            local brew_ok=0
            if command -v brew &> /dev/null; then
                if [ "${MACOS_LEGACY:-0}" -eq 1 ]; then
                    log_warning "Using Homebrew on macOS ${MACOS_VERSION}. If it fails, MacPorts will be used."
                fi

                log_info "Installing packages with Homebrew..."
                brew update || log_warning "Homebrew update failed. Continuing with install attempt."
                if ! brew install \
                    python@3.12 \
                    git \
                    wget \
                    curl \
                    nmap \
                    nikto \
                    go \
                    cairo \
                    gdk-pixbuf \
                    pango \
                    sqlite; then
                    log_warning "Homebrew installation failed."
                    if command -v port &> /dev/null; then
                        log_warning "Falling back to MacPorts."
                    else
                        log_error "MacPorts not found. Install MacPorts from https://www.macports.org and retry."
                        exit 1
                    fi
                else
                    log_success "Homebrew packages installed."
                    brew_ok=1
                fi
            fi

            if [ "$brew_ok" -eq 0 ] && command -v port &> /dev/null; then
                log_info "Installing packages with MacPorts..."
                sudo port -N selfupdate
                sudo port -N install \
                    python312 \
                    py312-pip \
                    git \
                    wget \
                    curl \
                    nmap \
                    nikto \
                    go \
                    cairo \
                    gdk-pixbuf2 \
                    pango \
                    sqlite3

                sudo port -N select --set python3 python312 || true
                sudo port -N select --set pip pip312 || true
            elif [ "$brew_ok" -eq 0 ]; then
                log_error "Neither Homebrew nor MacPorts is available."
                log_error "Install Homebrew (https://brew.sh) or MacPorts (https://www.macports.org) and retry."
                exit 1
            fi

            ;;
        windows)
            log_warning "Windows detected. System dependencies must be installed manually."
            log_warning "Use PowerShell and run installer.ps1 for automated setup."
            ;;
        *)
            log_error "Unsupported platform: $PLATFORM"
            exit 1
            ;;
    esac

    log_success "System dependencies installation completed"
}

# Install or upgrade Go from the official distribution (Linux only).
install_go_from_official() {
    log_info "Installing Go from the official distribution..."

    if [ "$PLATFORM" != "linux" ]; then
        log_warning "Official Go installer is supported only on Linux in this script."
        return 1
    fi

    local arch
    case "$(uname -m)" in
        x86_64)
            arch="amd64"
            ;;
        aarch64|arm64)
            arch="arm64"
            ;;
        *)
            log_warning "Unsupported architecture for Go install: $(uname -m)"
            return 1
            ;;
    esac

    local go_version
    if ! go_version=$(curl -fsSL https://go.dev/VERSION?m=text); then
        log_warning "Unable to fetch the latest Go version."
        return 1
    fi

    local tarball="${go_version}.linux-${arch}.tar.gz"
    local tmp_archive="/tmp/${tarball}"

    log_info "Downloading ${tarball}..."
    if ! curl -fsSL "https://dl.google.com/go/${tarball}" -o "$tmp_archive"; then
        log_warning "Failed to download Go archive."
        return 1
    fi

    log_info "Installing Go to /usr/local/go..."
    # NOTE: for maximum security, verify the SHA256 checksum before extracting.
    # Reference: https://go.dev/dl/ — each release lists its expected checksum.
    log_warning "Checksum verification of the Go tarball is recommended. See https://go.dev/dl/ for the expected SHA256."
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "$tmp_archive"
    rm -f "$tmp_archive"

    ensure_go_path
    log_success "Go ${go_version} installed from official distribution."
    return 0
}

# Configure Go environment variables and persist them for future shells.
setup_go_environment() {
    log_info "Configuring Go environment..."

    # Ensure Go is installed and available in PATH.
    if ! command -v go &> /dev/null; then
        if [ "$PLATFORM" = "linux" ]; then
            log_warning "Go not found. Attempting to install Go from official distribution."
            if ! install_go_from_official; then
                log_error "Go is not installed or not available in PATH."
                exit 1
            fi
        else
            log_error "Go is not installed or not available in PATH."
            exit 1
        fi
    fi

    # Configure GOPATH if missing.
    if [ -z "${GOPATH:-}" ]; then
        export GOPATH=$HOME/go
        export PATH=$PATH:$GOPATH/bin

        # Persist environment for future shells.
        if [ -f "$HOME/.bashrc" ]; then
            echo 'export GOPATH=$HOME/go' >> "$HOME/.bashrc"
            echo 'export PATH=$PATH:$GOPATH/bin' >> "$HOME/.bashrc"
        fi
        if [ -f "$HOME/.zshrc" ]; then
            echo 'export GOPATH=$HOME/go' >> "$HOME/.zshrc"
            echo 'export PATH=$PATH:$GOPATH/bin' >> "$HOME/.zshrc"
        fi
    fi
    
    local go_version
    go_version=$(go version | awk '{print $3}' | sed 's/go//')
    if [[ "$go_version" =~ ^([0-9]+)\.([0-9]+) ]]; then
        local major="${BASH_REMATCH[1]}"
        local minor="${BASH_REMATCH[2]}"
        if (( major < 1 || (major == 1 && minor < 19) )); then
            log_warning "Go ${go_version} rilevato. Nuclei v3 richiede Go >= 1.19."
            if [ "$PLATFORM" = "linux" ]; then
                log_warning "Tentativo di aggiornamento automatico di Go."
                if install_go_from_official; then
                    go_version=$(go version | awk '{print $3}' | sed 's/go//')
                    if [[ "$go_version" =~ ^([0-9]+)\.([0-9]+) ]]; then
                        major="${BASH_REMATCH[1]}"
                        minor="${BASH_REMATCH[2]}"
                    fi
                fi
            else
                log_warning "Aggiorna Go manualmente (es. brew upgrade go o https://go.dev/dl/)."
            fi
            if (( major < 1 || (major == 1 && minor < 19) )); then
                GO_TOO_OLD=1
            fi
        fi
    fi

    log_success "Go environment configured"
}

# Install external security tools used by the scanners.
install_security_tools() {
    log_info "Installing external security tools..."

    # Create a dedicated directory to keep third-party tools together.
    local tools_dir="$HOME/security-tools"
    local start_dir="$PWD"
    mkdir -p "$tools_dir"
    pushd "$tools_dir" >/dev/null

    # Install Nuclei via Go if missing.
    log_info "Installing Nuclei..."
    if [ "${GO_TOO_OLD:-0}" -eq 1 ]; then
        log_warning "Skipping Nuclei install because Go is outdated."
    elif ! command -v nuclei &> /dev/null; then
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        log_success "Nuclei installed"
    else
        log_success "Nuclei already installed"
    fi

    # Update Nuclei templates (best-effort).
    log_info "Updating Nuclei templates..."
    nuclei -update-templates -silent 2>/dev/null || true

    # Install Subfinder.
    log_info "Installing Subfinder..."
    if [ "${GO_TOO_OLD:-0}" -eq 1 ]; then
        log_warning "Skipping Subfinder install because Go is outdated."
    elif ! command -v subfinder &> /dev/null; then
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        log_success "Subfinder installed"
    else
        log_success "Subfinder already installed"
    fi

    # Install Assetfinder.
    log_info "Installing Assetfinder..."
    if [ "${GO_TOO_OLD:-0}" -eq 1 ]; then
        log_warning "Skipping Assetfinder install because Go is outdated."
    elif ! command -v assetfinder &> /dev/null; then
        go install github.com/tomnomnom/assetfinder@latest
        log_success "Assetfinder installed"
    else
        log_success "Assetfinder already installed"
    fi

    # Install WhatWeb when missing.
    log_info "Checking WhatWeb..."
    if ! command -v whatweb &> /dev/null; then
        local whatweb_dir="$HOME/security-tools/WhatWeb"
        log_info "Installing WhatWeb from GitHub..."

        if [ -d "$whatweb_dir" ]; then
            log_warning "WhatWeb directory already exists. Trying to update it..."
            if git -C "$whatweb_dir" rev-parse --is-inside-work-tree &> /dev/null; then
                git -C "$whatweb_dir" fetch --all --prune || log_warning "WhatWeb update failed. Using existing files."
            else
                log_warning "Existing WhatWeb directory is not a git repo. Skipping update."
            fi
        else
            if ! git clone https://github.com/urbanadventurer/WhatWeb.git "$whatweb_dir"; then
                log_warning "WhatWeb clone failed. Skipping installation."
            else
                log_success "WhatWeb repository cloned"
            fi
        fi

        if [ -d "$whatweb_dir" ]; then
            pushd "$whatweb_dir" >/dev/null
            ensure_local_bin_path
            ensure_psych_gem_for_whatweb
            if make install PREFIX="$HOME/.local"; then
                log_success "WhatWeb installed to ~/.local"
            else
                log_warning "WhatWeb make install failed. Falling back to local wrapper."
                mkdir -p "$HOME/.local/bin"
                cat << 'EOF' > "$HOME/.local/bin/whatweb"
#!/bin/bash
WHATWEB_HOME="$HOME/security-tools/WhatWeb"
exec "$WHATWEB_HOME/whatweb" "$@"
EOF
                chmod +x "$HOME/.local/bin/whatweb"
                log_success "WhatWeb wrapper installed to ~/.local/bin"
            fi
            popd >/dev/null
        else
            log_warning "WhatWeb directory not available. Continuing without WhatWeb."
        fi
    else
        log_success "WhatWeb already installed"
    fi

    # Install Dirsearch for content discovery.
    log_info "Installing Dirsearch..."
    if ! command -v dirsearch &> /dev/null; then
        local dirsearch_dir="$tools_dir/dirsearch"
        if [ -d "$dirsearch_dir" ]; then
            log_warning "Dirsearch directory already exists. Trying to update it..."
            if git -C "$dirsearch_dir" rev-parse --is-inside-work-tree &> /dev/null; then
                git -C "$dirsearch_dir" pull --ff-only || log_warning "Dirsearch update failed."
            else
                log_warning "Existing Dirsearch directory is not a git repo. Skipping update."
            fi
        else
            if ! git clone https://github.com/maurosoria/dirsearch.git "$dirsearch_dir"; then
                log_warning "Dirsearch clone failed. Skipping installation."
            else
                log_success "Dirsearch repository cloned"
            fi
        fi

        if [ -d "$dirsearch_dir" ]; then
            # Use the venv pip if available to avoid polluting the system Python environment.
            # Note: install_security_tools runs before create_python_venv, so the venv may not
            # exist yet; fall back to pip3 with --user to satisfy PEP 668 on managed systems.
            local _pip_cmd="pip3"
            local _pip_extra_args=()
            if [ -f "$start_dir/venv/bin/pip" ]; then
                _pip_cmd="$start_dir/venv/bin/pip"
            else
                _pip_extra_args=("--user")
            fi
            if ! "$_pip_cmd" install "${_pip_extra_args[@]}" -r "$dirsearch_dir/requirements.txt"; then
                log_warning "Dirsearch pip install failed. The wrapper script will still work if dependencies are already present."
            fi
            ensure_local_bin_path
            mkdir -p "$HOME/.local/bin"
            cat << EOF > "$HOME/.local/bin/dirsearch"
#!/usr/bin/env bash
python3 "$dirsearch_dir/dirsearch.py" "\$@"
EOF
            chmod +x "$HOME/.local/bin/dirsearch"
            log_success "Dirsearch installed"
        fi
    else
        log_success "Dirsearch already installed"
    fi

    popd >/dev/null
    cd "$start_dir"
    log_success "Security tools installed successfully"
}

# Create and activate the Python virtual environment.
create_python_venv() {
    log_info "Creating Python virtual environment..."

    # Remove old venv to ensure a clean state.
    if [ -d "venv" ]; then
        log_warning "Removing existing virtual environment..."
        rm -rf venv
    fi

    # Create venv using the selected Python binary.
    "$PYTHON_BIN" -m venv venv
    log_success "Virtual environment created"

    # Activate venv for dependency installation.
    source venv/bin/activate

    # Upgrade pip tooling for a clean install.
    log_info "Upgrading pip..."
    pip install --upgrade pip setuptools wheel

    log_success "Virtual environment configured"
}

# Install Python dependencies from requirements.txt.
install_python_dependencies() {
    log_info "Installing Python dependencies..."

    # Ensure venv is active.
    source venv/bin/activate

    # Resolve requirements path from the repository root.
    local requirements_file="${SCRIPT_DIR}/requirements.txt"

    # Install dependencies.
    if [ -f "$requirements_file" ]; then
        pip install -r "$requirements_file"
        log_success "Python dependencies installed"
    else
        log_error "requirements.txt not found at: $requirements_file"
        log_error "Current working directory: $(pwd)"
        log_error "Ensure you run the installer from the repository root."
        exit 1
    fi
}

# Create the directory structure used by the application.
create_directory_structure() {
    log_info "Creating directory structure..."

    mkdir -p reports logs scans static/css static/js templates scanners

    # Ensure scanners package is importable.
    touch scanners/__init__.py

    log_success "Directory structure created"
}

# Initialize the database schema.
initialize_database() {
    log_info "Initializing database..."

    source venv/bin/activate
    "$PYTHON_BIN" -c "from database import init_db; init_db()"

    log_success "Database initialized"
}

# Set safe permissions for runtime directories and scripts.
set_permissions() {
    log_info "Setting permissions..."

    chmod +x app.py
    chmod 755 reports logs scans

    log_success "Permissions configured"
}

# Verify installation completeness and report missing dependencies.
verify_installation() {
    log_info "Verifying installation..."

    local errors=0

    # Validate external tools.
    commands=("nmap" "nikto" "nuclei" "subfinder" "assetfinder" "whatweb")
    for cmd in "${commands[@]}"; do
        if command -v $cmd &> /dev/null; then
            log_success "$cmd: OK"
        else
            log_error "$cmd: NOT FOUND"
            ((errors++))
        fi
    done

    # Validate core Python packages.
    source venv/bin/activate
    "$PYTHON_BIN" << EOF
import sys
packages = ['fastapi', 'uvicorn', 'reportlab', 'sqlalchemy']
errors = 0
for pkg in packages:
    try:
        __import__(pkg)
        print(f"✓ {pkg}: OK")
    except ImportError:
        print(f"✗ {pkg}: NOT FOUND")
        errors += 1
sys.exit(errors)
EOF

    if [ $? -ne 0 ]; then
        ((errors++))
    fi

    if [ $errors -eq 0 ]; then
        log_success "Verification completed successfully!"
        return 0
    else
        log_error "Verification failed with $errors error(s)"
        return 1
    fi
}

# Print final instructions for the user.
print_final_instructions() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                  INSTALLATION COMPLETE!                    ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}📋 NEXT STEPS:${NC}"
    echo ""
    echo -e "1️⃣  Activate the virtual environment:"
    echo -e "   ${YELLOW}source venv/bin/activate${NC}"
    echo ""
    echo -e "2️⃣  Start the server:"
    echo -e "   ${YELLOW}${PYTHON_BIN} app.py${NC}"
    echo ""
    echo -e "3️⃣  Open your browser at:"
    echo -e "   ${YELLOW}http://localhost:8000${NC}"
    echo ""
    echo -e "${BLUE}📚 USEFUL COMMANDS:${NC}"
    echo -e "   • Start with verbose logs: ${YELLOW}${PYTHON_BIN} app.py --debug${NC}"
    echo -e "   • Run a CLI scan: ${YELLOW}${PYTHON_BIN} scanner_engine.py --target <URL>${NC}"
    echo ""
    echo -e "${BLUE}📄 INSTALLATION LOGS:${NC}"
    echo -e "   • Full log:        ${YELLOW}${LOG_FILE}${NC}"
    echo -e "   • Errors-only log: ${YELLOW}${ERROR_LOG_FILE}${NC}"
    echo ""
    echo -e "${RED}⚠️  DISCLAIMER:${NC}"
    echo -e "   This tool is intended ONLY for authorized testing."
    echo -e "   Unauthorized usage may violate local and international laws."
    echo ""
}

# Error analysis handler with context-rich logs.
on_error() {
    local exit_code=$?
    local line_number=$1
    local command=$2
    log_error "Installation failed (exit code: ${exit_code})."
    log_error "Command: ${command}"
    log_error "Line: ${line_number}"
    log_error "Check the log file for details: ${LOG_FILE}"
    log_error "Errors-only log: ${ERROR_LOG_FILE}"
    log_to_file "ERROR: exit_code=${exit_code} line=${line_number} command=${command}"
    log_error_to_file "exit_code=${exit_code} line=${line_number} command=${command}"
    exit "$exit_code"
}

trap 'on_error ${LINENO} "$BASH_COMMAND"' ERR

# Main execution flow.
main() {
    clear
    print_logo

    log_info "Starting Vulnerability Assessment Platform installation..."
    echo ""

    check_required_files
    check_root
    detect_platform
    install_system_dependencies

    if [ "$PLATFORM" != "windows" ]; then
        check_python_version
        setup_go_environment
        install_security_tools
        create_directory_structure
        create_python_venv
        install_python_dependencies
        initialize_database
        set_permissions
    else
        log_warning "Skipping Unix-specific steps. Use installer.ps1 on Windows."
    fi

    echo ""
    if [ "$PLATFORM" = "windows" ]; then
        log_warning "Verification skipped on Windows. Use installer.ps1 for validation."
        log_info "Windows setup guide: powershell -ExecutionPolicy Bypass -File installer.ps1"
        exit 0
    fi

    if verify_installation; then
        print_final_instructions
    else
        log_error "Installation completed with errors. Review the messages above."
        exit 1
    fi
}

# Run the installer.
main "$@"
