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

test: ## Run tests
	pytest -v

test-cov: ## Run tests with coverage
	pytest --cov=src --cov-report=html --cov-report=term

format: ## Format code with black
	black src/ tests/

lint: ## Lint code with flake8
	flake8 src/ tests/

type-check: ## Type check with mypy
	mypy src/

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
