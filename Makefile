.PHONY: help install install-dev install-prod test format lint clean run

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

install: install-dev ## Install development dependencies (default)

install-dev: ## Install development dependencies (includes production + testing tools)
	pip install -r requirements-dev.txt

install-prod: ## Install production dependencies only
	pip install -r requirements.txt

# Detect if we're in a virtual environment or use venv if available
PYTHON := $(shell which python3 || which python)
VENV_PYTHON := $(shell if [ -f venv/bin/python ]; then echo venv/bin/python; else echo $(PYTHON); fi)
PYTEST := $(VENV_PYTHON) -m pytest

test: ## Run unit tests
	$(PYTEST) -v -m "not integration"

test-integration: ## Run integration tests (requires Docker services and API server)
	@echo "Checking Docker services..."
	@(docker compose -f tests/integration/config/docker-compose.yaml ps redis rabbitmq clickhouse redpanda 2>/dev/null | grep -q "redis\|rabbitmq\|clickhouse\|redpanda" || docker-compose -f tests/integration/config/docker-compose.yaml ps redis rabbitmq clickhouse redpanda 2>/dev/null | grep -q "redis\|rabbitmq\|clickhouse\|redpanda" || sudo docker compose -f tests/integration/config/docker-compose.yaml ps redis rabbitmq clickhouse redpanda 2>/dev/null | grep -q "redis\|rabbitmq\|clickhouse\|redpanda") || (echo "ERROR: Docker services not running. Start with: make integration-up" && exit 1)
	@echo "Running integration tests..."
	$(PYTEST) tests/integration/ -v -m integration

integration-up: ## Start integration test services
	@echo "Starting integration test services..."
	@cd tests/integration/config && \
	if docker compose version &> /dev/null 2>&1; then \
		docker compose -f docker-compose.yaml up -d redis rabbitmq clickhouse redpanda api-server || \
		sudo docker compose -f docker-compose.yaml up -d redis rabbitmq clickhouse redpanda api-server; \
	elif docker-compose version &> /dev/null 2>&1; then \
		docker-compose -f docker-compose.yaml up -d redis rabbitmq clickhouse redpanda api-server || \
		sudo docker-compose -f docker-compose.yaml up -d redis rabbitmq clickhouse redpanda api-server; \
	else \
		sudo docker compose -f docker-compose.yaml up -d redis rabbitmq clickhouse redpanda api-server; \
	fi

integration-down: ## Stop integration test services
	@echo "Stopping integration test services..."
	@cd tests/integration/config && \
	if docker compose version &> /dev/null 2>&1; then \
		docker compose -f docker-compose.yaml down || \
		sudo docker compose -f docker-compose.yaml down; \
	elif docker-compose version &> /dev/null 2>&1; then \
		docker-compose -f docker-compose.yaml down || \
		sudo docker-compose -f docker-compose.yaml down; \
	else \
		sudo docker compose -f docker-compose.yaml down; \
	fi

integration-logs: ## Show integration test service logs
	@cd tests/integration/config && \
	if docker compose version &> /dev/null 2>&1; then \
		docker compose -f docker-compose.yaml logs -f || \
		sudo docker compose -f docker-compose.yaml logs -f; \
	elif docker-compose version &> /dev/null 2>&1; then \
		docker-compose -f docker-compose.yaml logs -f || \
		sudo docker-compose -f docker-compose.yaml logs -f; \
	else \
		sudo docker compose -f docker-compose.yaml logs -f; \
	fi

test-all: ## Run all tests (unit + integration)
	$(PYTEST) -v

test-cov: ## Run tests with coverage
	$(PYTEST) --cov=src --cov-report=html --cov-report=term

format: ## Format code with black
	$(VENV_PYTHON) -m black src/ tests/

lint: ## Lint code with flake8
	$(VENV_PYTHON) -m flake8 src/ tests/

type-check: ## Type check with mypy
	$(VENV_PYTHON) -m mypy src/

clean: ## Clean cache and temporary files
	find . -type d -name __pycache__ -exec rm -r {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type d -name "*.egg-info" -exec rm -r {} + 2>/dev/null || true
	rm -rf .pytest_cache .coverage htmlcov/ .mypy_cache

run: ## Run the development server
	uvicorn src.main:app --reload --port 8000

run-prod: ## Run production server
	uvicorn src.main:app --host 0.0.0.0 --port 8000 --workers 4

docker-build: ## Build Docker image
	docker-compose build

docker-up: ## Start Docker services
	docker-compose up -d

docker-down: ## Stop Docker services
	docker-compose down

docker-logs: ## View Docker logs
	docker-compose logs -f
