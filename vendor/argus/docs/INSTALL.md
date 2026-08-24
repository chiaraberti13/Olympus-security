# 📦 Installation Guide (English)

> 🇮🇹 Versione italiana: [INSTALL.it.md](INSTALL.it.md)

This guide covers **Windows**, **Ubuntu/Debian Linux** and **macOS**, with both
the fully automated one-command installer and manual step-by-step instructions,
plus troubleshooting.

- [Requirements](#requirements)
- [Ubuntu / Debian Linux](#-ubuntu--debian-linux)
- [macOS](#-macos)
- [Windows](#-windows)
- [Docker (any OS)](#-docker-any-os)
- [Verifying the installation](#-verifying-the-installation)
- [Updating](#-updating)
- [Uninstalling](#-uninstalling)
- [Troubleshooting](#-troubleshooting)

---

## Requirements

- **Python 3.8 or newer** (the installers can install it for you)
- **git** (to clone the repository)
- Internet access (the tool queries public OSINT services)

Everything else (`requests`, `phonenumbers`, `rich`) is installed automatically
into an isolated virtual environment, so your system Python stays clean.

---

## 🐧 Ubuntu / Debian Linux

### Option A — Automated (recommended)

```bash
# 1. Install git if you don't have it
sudo apt update && sudo apt install -y git

# 2. Clone the project
git clone https://github.com/chiaraberti13/prova.git argus
cd argus

# 3. Run the installer (it will use sudo only if Python/venv is missing)
./scripts/install.sh

# Optional flavors:
./scripts/install.sh --with-dns    # enables real MX-record checks (email module)
./scripts/install.sh --dev         # also installs pytest + ruff for development
```

The script will:
1. Detect Ubuntu/Debian and check for Python 3.8+, `venv` and `pip`
   (installing them via `apt` if missing).
2. Create a virtual environment in `./.venv`.
3. Install Argus and its dependencies.
4. Create a `argus` launcher in `~/.local/bin` and add it to your `PATH`.

Then simply run:
```bash
argus
```
If the command isn't found, reload your shell: `source ~/.bashrc` (or open a new terminal).

### Option B — Manual

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git
git clone https://github.com/chiaraberti13/prova.git argus
cd argus
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .
python -m argus        # run it
```

---

## 🍎 macOS

### Option A — Automated (recommended)

```bash
# If you don't have Homebrew, install it first (recommended):
#   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

git clone https://github.com/chiaraberti13/prova.git argus
cd argus
chmod +x scripts/install.sh
./scripts/install.sh
```

The installer will use **Homebrew** to install Python if it's missing. If you
don't use Homebrew, install Python 3.8+ from [python.org](https://www.python.org/downloads/macos/)
first, then re-run the script.

Launch it:
```bash
argus
```
If not found, add the launcher directory to your shell profile:
```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

### Option B — Manual

```bash
brew install python git          # or install Python from python.org
git clone https://github.com/chiaraberti13/prova.git argus
cd argus
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .
python -m argus
```

---

## 🪟 Windows

### Option A — Automated (recommended)

1. Install **Git for Windows**: <https://git-scm.com/download/win>
   (Python is optional — the installer can fetch it via `winget`.)
2. Open **PowerShell** and run:

```powershell
git clone https://github.com/chiaraberti13/prova.git argus
cd argus
powershell -ExecutionPolicy Bypass -File scripts\install.ps1

# Optional flavors:
#   -WithDns   enable real MX-record checks
#   -Dev       install pytest + ruff
```

The script will:
1. Find Python 3.8+ (or install Python 3.12 via `winget` if missing).
2. Create a virtual environment in `.\.venv`.
3. Install Argus.
4. Create `argus.cmd` in `%LOCALAPPDATA%\Programs\Argus\bin` and add it to your user `PATH`.

**Open a new terminal**, then:
```powershell
argus
```

> If you see *"running scripts is disabled on this system"*, you either invoked
> PowerShell with `-ExecutionPolicy Bypass` (as above — recommended) or you can
> allow scripts for your user once:
> `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

### Option B — Manual

```powershell
# Install Python 3.8+ from https://python.org (check "Add python.exe to PATH")
git clone https://github.com/chiaraberti13/prova.git argus
cd argus
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -e .
python -m argus
```

---

## 🐳 Docker (any OS)

No local Python required — just Docker.

```bash
git clone https://github.com/chiaraberti13/prova.git argus
cd argus
docker build -t argus .

# Interactive menu
docker run --rm -it argus

# One-off command
docker run --rm argus username torvalds

# Keep reports on the host (mount a volume)
docker run --rm -v "$PWD/reports:/reports" argus ip 8.8.8.8 --export html
```

---

## ✅ Verifying the installation

```bash
argus --version                 # prints: Argus 3.0.0
argus phone "+14155552671"      # works fully offline — good smoke test
```

If the `argus` command isn't found, you can always run it explicitly:
```bash
# Linux/macOS
.venv/bin/python -m argus
# Windows
.venv\Scripts\python.exe -m argus
```

---

## 🔄 Updating

```bash
cd argus
git pull
# then re-run the installer (idempotent) or, inside the venv:
pip install -e . --upgrade
```

---

## 🧹 Uninstalling

```bash
# Remove the virtual environment and reports
rm -rf .venv report                   # Windows: rmdir /s .venv report

# Remove the launcher
rm ~/.local/bin/argus                 # Linux/macOS
# Windows: delete %LOCALAPPDATA%\Programs\Argus and remove it from PATH

# Finally, delete the cloned folder
cd .. && rm -rf argus
```

---

## 🛠️ Troubleshooting

| Symptom | Fix |
|---------|-----|
| `argus: command not found` | Open a new terminal, or add `~/.local/bin` (Linux/macOS) / the launcher dir (Windows) to `PATH`. You can always use `python -m argus` from inside the venv. |
| `python3: command not found` (Linux) | `sudo apt install python3 python3-venv python3-pip` |
| `externally-managed-environment` pip error | This is expected on modern distros — that's exactly why we use a **virtual environment**. Don't `pip install` globally; use the installer or the venv. |
| PowerShell: *running scripts is disabled* | Run with `-ExecutionPolicy Bypass` (shown above) or `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`. |
| SSL / proxy errors behind a corporate proxy | Set `HTTPS_PROXY`, or as a last resort `ARGUS_NO_VERIFY_SSL=1` (not recommended). |
| Username results look like false positives | Some sites return HTTP 200 for any URL. Increase `--timeout`, or refine a site's entry in `data/sites.json` to use the `text` detection method. |
| Email module says MX = *unknown* | Install the optional dependency: `pip install dnspython` (or re-install with `--with-dns`). |

Still stuck? Open an issue with your OS, Python version (`python3 --version`),
and the exact error message.
