.PHONY: install lint type test check demo clean mars-up mars-down mars-status

PYTHON ?= python
MARS_COMPOSE = docker compose -f labs/mars/docker-compose.yml

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

# Mars cyber range: segmented, non-destructive, synthetic-data-only target
# environment (see labs/mars/README.md). `up`/`down` only ever touch the
# `mars` Compose project's own containers/network -- never anything else
# on the host.
mars-up:
	$(MARS_COMPOSE) up -d

mars-down:
	$(MARS_COMPOSE) down

mars-status:
	$(MARS_COMPOSE) ps
