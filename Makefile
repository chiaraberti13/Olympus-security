.PHONY: install lint type test check demo clean

PYTHON ?= python

install:
	$(PYTHON) -m pip install -e ".[dev]"

# --------------------------------------------------------------------------- #
# Optional quality helpers. None of these are a completion gate: linting, type
# checking, tests, and coverage are optional tools that must never block
# implementation, integration, execution, or calling a tool "complete".
# Completeness means 100% functional feature parity, not a passing gate.
# --------------------------------------------------------------------------- #
lint:
	$(PYTHON) -m ruff check .

type:
	$(PYTHON) -m mypy .

test:
	$(PYTHON) -m pytest

# `check` runs the optional helpers for convenience and never fails the build
# (leading '-' tells make to ignore their exit status).
check:
	-$(MAKE) lint
	-$(MAKE) type
	-$(MAKE) test

demo:
	olympus core export-schemas ./examples/output

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov build dist *.egg-info
