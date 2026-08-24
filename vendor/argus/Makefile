# Argus — developer convenience targets.
# Usage: make <target>

PYTHON ?= python3
VENV   := .venv
BIN    := $(VENV)/bin

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: install
install: ## Automated install (Linux/macOS)
	./scripts/install.sh

.PHONY: venv
venv: ## Create venv and install package in editable mode
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -e '.[dev]'

.PHONY: run
run: ## Launch the interactive menu
	$(BIN)/python -m argus

.PHONY: test
test: ## Run the offline test suite
	$(BIN)/pytest -q

.PHONY: lint
lint: ## Lint with ruff
	$(BIN)/ruff check argus tests

.PHONY: clean
clean: ## Remove venv, caches and build artifacts
	rm -rf $(VENV) build dist *.egg-info .pytest_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +

.PHONY: docker
docker: ## Build the Docker image
	docker build -t argus:latest .
