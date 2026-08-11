.PHONY: install lint type test check demo clean

PYTHON ?= python

install:
	$(PYTHON) -m pip install -e ".[dev]"

lint:
	$(PYTHON) -m ruff check .

type:
	$(PYTHON) -m mypy .

test:
	$(PYTHON) -m pytest

check: lint type test   ## the single gate: "green or not done"

demo:
	olympus core export-schemas ./examples/output

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov build dist *.egg-info
