.DEFAULT_GOAL := help
PY ?= python

.PHONY: help install dev test cov lint format typecheck build check clean run-daemon run-investigator

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-18s\033[0m %s\n", $$1, $$2}'

install: ## Install the package
	$(PY) -m pip install -e .

dev: ## Install with dev + fs extras
	$(PY) -m pip install -e ".[dev,fs]"

test: ## Run the test suite
	pytest

cov: ## Run tests with coverage
	pytest --cov=ares --cov-report=term-missing

lint: ## Lint with ruff
	ruff check src tests

format: ## Auto-format with ruff
	ruff format src tests
	ruff check --fix src tests

typecheck: ## Type-check with mypy
	mypy

build: ## Build sdist + wheel and verify metadata
	$(PY) -m build
	twine check dist/*

check: lint test ## Lint + test (what CI gates on)

clean: ## Remove build artifacts and caches
	rm -rf dist build *.egg-info src/*.egg-info .pytest_cache .ruff_cache .mypy_cache .coverage htmlcov

run-daemon: ## Run the telemetry daemon (dev)
	ares daemon run

run-investigator: ## Run one investigation cycle (dev)
	ares investigator run --once
