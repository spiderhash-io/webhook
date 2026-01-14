.PHONY: help install install-dev install-prod test format lint type-check security-scan security-bandit security-safety clean run docker-build-multiarch docker-push-multiarch

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

test: ## Run unit tests (excludes integration, external_services, and longrunning)
	$(PYTEST) -v -m "not integration and not external_services and not longrunning"

test-integration: ## Run integration tests (requires Docker services and API server, excludes longrunning and external_services)
	@echo "Checking Docker services..."
	@(docker compose -f tests/integration/config/docker-compose.yaml ps redis rabbitmq clickhouse redpanda 2>/dev/null | grep -q "redis\|rabbitmq\|clickhouse\|redpanda" || docker-compose -f tests/integration/config/docker-compose.yaml ps redis rabbitmq clickhouse redpanda 2>/dev/null | grep -q "redis\|rabbitmq\|clickhouse\|redpanda" || sudo docker compose -f tests/integration/config/docker-compose.yaml ps redis rabbitmq clickhouse redpanda 2>/dev/null | grep -q "redis\|rabbitmq\|clickhouse\|redpanda") || (echo "ERROR: Docker services not running. Start with: make integration-up" && exit 1)
	@echo "Running integration tests..."
	$(PYTEST) tests/integration/ -v -m "integration and not longrunning and not external_services"

test-external-services: ## Run tests that require external services (ClickHouse, Redis, Kafka, PostgreSQL)
	@echo "Running tests that require external services..."
	@echo "Make sure ClickHouse, Redis, Kafka, and PostgreSQL are running!"
	$(PYTEST) -v -m "external_services"

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

test-all: ## Run all tests (unit + integration, excludes longrunning and external_services)
	$(PYTEST) -v -m "not longrunning and not external_services"

test-longrunning: ## Run long-running tests (use with caution, these tests take a long time)
	$(PYTEST) -v -m longrunning

test-cov: ## Run tests with coverage (excludes longrunning and todo)
	$(PYTEST) --cov=src --cov-report=html --cov-report=term -m "not longrunning and not todo"

format: ## Format code with black
	$(VENV_PYTHON) -m black src/ tests/

lint: ## Lint code with flake8
	$(VENV_PYTHON) -m flake8 src/ tests/

type-check: ## Type check with mypy
	$(VENV_PYTHON) -m mypy src/

security-scan: security-bandit security-safety ## Run all security scans (Bandit + Safety)

security-bandit: ## Run Bandit security scanner on source code
	@echo "Running Bandit security scanner..."
	$(VENV_PYTHON) -m bandit -r src/ -f json -o bandit-report.json --skip B608 || true
	$(VENV_PYTHON) -m bandit -r src/ -f screen --skip B608

security-safety: ## Check dependencies for known security vulnerabilities
	@echo "Running Safety dependency checker on production dependencies (requirements.txt)..."
	$(VENV_PYTHON) -m safety check --file requirements.txt --json --output safety-report.json || true
	$(VENV_PYTHON) -m safety check --file requirements.txt || echo "Note: Safety requires internet for first run to download vulnerability database. Subsequent runs can work offline if DB is cached."
	@echo ""
	@echo "Note: Dev tools (setuptools, pip, urllib3) vulnerabilities are not checked as they are not runtime dependencies." || echo "Note: Safety requires internet for first run to download vulnerability database. Subsequent runs can work offline if DB is cached."

clean: ## Clean cache and temporary files
	find . -type d -name __pycache__ -exec rm -r {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type d -name "*.egg-info" -exec rm -r {} + 2>/dev/null || true
	rm -rf .pytest_cache .coverage htmlcov/ .mypy_cache bandit-report.json safety-report.json

run: ## Run the development server
	uvicorn src.main:app --reload --port 8000

run-prod: ## Run production server
	uvicorn src.main:app --host 0.0.0.0 --port 8000 --workers 4

docker-build: ## Build Docker image
	docker-compose -f docker/compose/docker-compose.yaml build

docker-build-multiarch: DOCKER_TAG ?= latest
docker-build-multiarch: ## Build multi-architecture Docker image (linux/amd64,linux/arm64) - builds only, use docker-build-multiarch-push to push
	@echo "Setting up buildx builder..."
	@docker buildx create --name multiarch --use 2>/dev/null || docker buildx use multiarch
	@docker buildx inspect --bootstrap > /dev/null 2>&1 || docker buildx inspect --bootstrap
	@echo "Building multi-architecture image with tag: $(DOCKER_TAG) (build only, not pushed)"
	@docker buildx build --platform linux/amd64,linux/arm64 \
		-f docker/Dockerfile.small \
		-t spiderhash/webhook:$(DOCKER_TAG) \
		-t spiderhash/webhook:latest \
		.

docker-build-multiarch-push: DOCKER_TAG ?= latest
docker-build-multiarch-push: ## Build and push multi-architecture Docker image (use DOCKER_TAG=0.1.0 to specify version)
	@echo "Setting up buildx builder..."
	@docker buildx create --name multiarch --use 2>/dev/null || docker buildx use multiarch
	@docker buildx inspect --bootstrap > /dev/null 2>&1 || docker buildx inspect --bootstrap
	@echo "Building and pushing multi-architecture image with tag: $(DOCKER_TAG)"
	@docker buildx build --platform linux/amd64,linux/arm64 \
		-f docker/Dockerfile.small \
		-t spiderhash/webhook:$(DOCKER_TAG) \
		-t spiderhash/webhook:latest \
		--push .

docker-up: ## Start Docker services
	docker-compose -f docker/compose/docker-compose.yaml up -d

docker-down: ## Stop Docker services
	docker-compose -f docker/compose/docker-compose.yaml down

docker-logs: ## View Docker logs
	docker-compose -f docker/compose/docker-compose.yaml logs -f
