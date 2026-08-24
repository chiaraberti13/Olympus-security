#!/usr/bin/env bash
#
# Argus automated installer for Ubuntu/Debian Linux and macOS.
#
# What it does (idempotent — safe to re-run):
#   1. Detects the OS and package manager.
#   2. Ensures Python 3.8+, pip and venv are available (auto-installs on
#      Ubuntu/Debian via apt, on macOS via Homebrew if present).
#   3. Creates an isolated virtual environment in ./.venv.
#   4. Installs Argus and its dependencies into that venv.
#   5. Installs a `argus` launcher into ~/.local/bin (added to PATH).
#
# Usage:
#   ./scripts/install.sh            # normal install
#   ./scripts/install.sh --with-dns # also install dnspython (better email OSINT)
#   ./scripts/install.sh --dev      # also install dev/test tools
#
set -euo pipefail

# ------------------------------------------------------------------ colors --
if [ -t 1 ]; then
  BOLD="$(printf '\033[1m')"; GREEN="$(printf '\033[92m')"; YELLOW="$(printf '\033[93m')"
  RED="$(printf '\033[91m')"; CYAN="$(printf '\033[96m')"; RESET="$(printf '\033[0m')"
else
  BOLD=""; GREEN=""; YELLOW=""; RED=""; CYAN=""; RESET=""
fi
info()  { echo "${CYAN}[*]${RESET} $*"; }
ok()    { echo "${GREEN}[+]${RESET} $*"; }
warn()  { echo "${YELLOW}[!]${RESET} $*"; }
die()   { echo "${RED}[x]${RESET} $*" >&2; exit 1; }

# ------------------------------------------------------------------- paths --
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VENV_DIR="$REPO_DIR/.venv"
BIN_DIR="$HOME/.local/bin"

WITH_DNS=0
DEV=0
for arg in "$@"; do
  case "$arg" in
    --with-dns) WITH_DNS=1 ;;
    --dev) DEV=1 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) warn "unknown option: $arg" ;;
  esac
done

echo "${BOLD}Argus installer${RESET}"
info "Repository: $REPO_DIR"

# ------------------------------------------------------------- detect OS ----
OS="unknown"
case "$(uname -s)" in
  Linux*)  OS="linux" ;;
  Darwin*) OS="macos" ;;
  *) die "Unsupported OS: $(uname -s). Use scripts/install.ps1 on Windows." ;;
esac
info "Detected OS: $OS"

# ----------------------------------------------- ensure python toolchain ----
ensure_python_linux() {
  if command -v python3 >/dev/null 2>&1 && python3 -m venv --help >/dev/null 2>&1 \
     && python3 -m pip --version >/dev/null 2>&1; then
    return
  fi
  warn "Python 3 / venv / pip missing — installing via apt (sudo required)."
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -y
    sudo apt-get install -y python3 python3-venv python3-pip
  else
    die "Automatic install only supports apt. Please install Python 3.8+ manually."
  fi
}

ensure_python_macos() {
  if command -v python3 >/dev/null 2>&1; then return; fi
  warn "Python 3 missing."
  if command -v brew >/dev/null 2>&1; then
    info "Installing Python via Homebrew…"
    brew install python
  else
    die "Python 3 not found and Homebrew is not installed. Install Python 3.8+ from python.org, then re-run."
  fi
}

if [ "$OS" = "linux" ]; then ensure_python_linux; else ensure_python_macos; fi

PY="$(command -v python3)"
PYVER="$("$PY" -c 'import sys; print("%d.%d"%sys.version_info[:2])')"
info "Using Python $PYVER at $PY"
"$PY" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3,8) else 1)' \
  || die "Python 3.8+ required, found $PYVER."

# --------------------------------------------------- create virtualenv ------
info "Creating virtual environment in .venv …"
"$PY" -m venv "$VENV_DIR"
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
python -m pip install --upgrade pip >/dev/null

# ------------------------------------------------------ install package -----
info "Installing Argus and dependencies …"
pip install -e "$REPO_DIR"
[ "$WITH_DNS" = "1" ] && { info "Installing dnspython (better email OSINT) …"; pip install "dnspython>=2.4.0"; }
[ "$DEV" = "1" ] && { info "Installing dev tools …"; pip install "pytest>=7.0" "pytest-mock>=3.10" "ruff>=0.1.0"; }
ok "Package installed into virtualenv."

# ------------------------------------------------- global launcher ----------
mkdir -p "$BIN_DIR"
LAUNCHER="$BIN_DIR/argus"
cat > "$LAUNCHER" <<EOF
#!/usr/bin/env bash
# Auto-generated Argus launcher
source "$VENV_DIR/bin/activate"
exec python -m argus "\$@"
EOF
chmod +x "$LAUNCHER"
ok "Launcher installed: $LAUNCHER"

# --------------------------------------------------- PATH hint --------------
case ":$PATH:" in
  *":$BIN_DIR:"*) : ;;
  *)
    warn "$BIN_DIR is not on your PATH."
    SHELL_RC="$HOME/.bashrc"
    [ -n "${ZSH_VERSION:-}" ] || [ "$(basename "${SHELL:-}")" = "zsh" ] && SHELL_RC="$HOME/.zshrc"
    echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "$SHELL_RC"
    ok "Added ~/.local/bin to PATH in $SHELL_RC (restart your shell or run: source $SHELL_RC)"
    ;;
esac

echo
ok "${BOLD}Installation complete!${RESET}"
echo "  Run it with:            ${CYAN}argus${RESET}"
echo "  Or a one-off command:   ${CYAN}argus ip 8.8.8.8${RESET}"
echo "  Without the launcher:   ${CYAN}$VENV_DIR/bin/python -m argus${RESET}"
