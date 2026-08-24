#!/usr/bin/env bash
# Quick launcher: activates the local venv (if present) and runs Argus.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ -d "$DIR/.venv" ]; then
  # shellcheck disable=SC1091
  source "$DIR/.venv/bin/activate"
fi
exec python -m argus "$@"
