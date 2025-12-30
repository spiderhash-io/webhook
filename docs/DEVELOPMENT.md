# Development Guide

This guide covers setting up and working with the development environment.

## Prerequisites

- Python 3.9 or higher
- pip (Python package manager)
- Git

## Initial Setup (Local venv)

### 1. Clone the Repository

```bash
git clone <repository-url>
cd core-webhook-module
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Development Dependencies

```bash
# Install all dependencies (production + development tools)
pip install -r requirements-dev.txt
```

Or use the Makefile:

```bash
make install-dev
```

## Development Workflow (Local)

### Running the Server (Local)

```bash
# Development mode with auto-reload
make run
# or
uvicorn src.main:app --reload --port 8000
```

### Running Tests (Local venv)

```bash
# 1) Activate venv (if not already)
source venv/bin/activate

# 2) Run all unit/integration tests
make test           # equivalent to: pytest -v

# 3) Run with coverage
make test-cov       # equivalent to: pytest --cov=src --cov-report=html --cov-report=term

# 4) Run a single test file (example)
pytest src/tests/test_webhook_flow.py -v
```

### Code Quality

```bash
# Format code
make format
# or
black src/ tests/

# Lint code
make lint
# or
flake8 src/ tests/

# Type checking
make type-check
# or
mypy src/
```

### Clean Up

```bash
# Remove cache and temporary files
make clean
```

## Project Structure

```
core-webhook-module/
├── src/                    # Source code
│   ├── main.py            # FastAPI app entry point
│   ├── webhook.py         # Webhook processing logic
│   ├── config.py          # Configuration loading
│   ├── modules/           # Output modules
│   ├── validators.py      # Validation logic
│   └── tests/             # Test files
├── requirements.txt       # Production dependencies
├── requirements-dev.txt   # Development dependencies
├── Makefile              # Development commands
├── .editorconfig         # Editor configuration
└── .python-version       # Python version specification
```

## Dependencies

### Production Dependencies (`requirements.txt`)

Core runtime dependencies needed for the application to run:
- FastAPI, Pydantic, Uvicorn (web framework)
- Redis, RabbitMQ clients
- HTTP clients (requests, httpx)
- Authentication (PyJWT)
- Database drivers (ClickHouse)
- Validation (jsonschema)

### Development Dependencies (`requirements-dev.txt`)

Additional tools for development and testing:
- **pytest** - Testing framework
- **pytest-asyncio** - Async test support
- **fakeredis** - Redis mock for testing
- **black** - Code formatter
- **flake8** - Linter
- **mypy** - Type checker
- **pytest-cov** - Coverage reporting

## Environment Variables

The project uses environment variables for configuration. Create a `.env` file in the root directory:

```bash
# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6380

# ClickHouse Configuration
CLICKHOUSE_HOST=localhost
CLICKHOUSE_PORT=9000

# Add other environment variables as needed
```

See `README.md` for more details on environment variable usage in configuration files.

## Testing

### Running Tests

```bash
# All tests
pytest

# Specific test file
pytest src/tests/test_env_vars.py

# With verbose output
pytest -v

# With coverage
pytest --cov=src --cov-report=html
```

### Writing Tests

- Place test files in `src/tests/`
- Test files should start with `test_`
- Use pytest fixtures for setup/teardown
- Mock external dependencies (Redis, HTTP calls, etc.)

## Code Style

The project uses:
- **Black** for code formatting (120 character line length)
- **flake8** for linting
- **mypy** for type checking

Run `make format` before committing code.

## Docker Workflows

This project supports three common workflows:

- **Local venv**: Fast inner-loop development and running the full test suite.
- **Single-instance Docker**: Run one FastAPI instance in a container (no Redis/ClickHouse required unless your config uses them).
- **Full multi-instance Docker (with Redis & ClickHouse)**: 5 webhook instances + Redis + ClickHouse + RabbitMQ + analytics service, mainly for performance/load testing.

### 1. Single-Instance Docker (App Only)

Use this when you just want the webhook service running in Docker on your machine.

**Step 1 – Build the image (optimized small image):**

```bash
# From project root
docker build -f Dockerfile.small -t core-webhook-module:small .
```

**Step 2 – Prepare configuration files:**

- `webhooks.json` – webhook definitions (you can copy/modify `webhooks.example.json`)
- `connections.json` – connections for modules (you can copy/modify `connections.example.json`)
- Optional: `.env` – environment variables used in configs

```bash
cp webhooks.example.json webhooks.json
cp connections.example.json connections.json
```

Adjust these files so that:
- You only enable modules you actually have backends for (e.g., disable ClickHouse modules if you don’t have ClickHouse running).
- Or point Redis/ClickHouse hosts to external services you manage separately.

**Step 3 – Run a single container:**

```bash
docker run --rm \
  -p 8000:8000 \
  -v "$(pwd)/webhooks.json:/app/webhooks.json:ro" \
  -v "$(pwd)/connections.json:/app/connections.json:ro" \
  --env-file .env \
  core-webhook-module:small
```

Now the service is available at:

- API root: `http://localhost:8000/`
- OpenAPI docs (Swagger UI): `http://localhost:8000/docs`
- ReDoc docs: `http://localhost:8000/redoc`

### 2. Full Multi-Instance Docker (Redis + ClickHouse + RabbitMQ)

Use this for **load/performance testing** and for seeing the complete architecture (5 webhook instances, analytics, Redis, ClickHouse, RabbitMQ).

**Step 1 – Start all services with Docker Compose:**

```bash
docker-compose up -d
```

This starts:
- `webhook-1` … `webhook-5` (ports 8000–8004)
- `analytics` (analytics processor)
- `redis` (exposed on host port 6380)
- `rabbitmq` (ports 5672, 15672)
- `clickhouse` (ports 8123, 9000)

**Step 2 – Verify services are up:**

```bash
docker-compose ps

# Check a webhook instance
curl http://localhost:8000/

# Check docs for an instance
curl http://localhost:8000/docs
```

**Step 3 – Run performance tests (optional but recommended):**

```bash
# Quick automated run
./src/tests/run_performance_test.sh

# Or manual:
python3 src/tests/performance_test_multi_instance.py
```

See `docs/PERFORMANCE_TEST.md` for detailed performance test options and how to inspect ClickHouse data.

**Step 4 – Inspect logs and stop services:**

```bash
# Logs
docker-compose logs -f

# Stop and remove services
docker-compose down

# Stop and also remove volumes (including ClickHouse data)
docker-compose down -v
```

## Common Tasks

### Adding a New Dependency

1. **Production dependency**: Add to `requirements.txt`
2. **Development dependency**: Add to `requirements-dev.txt`
3. Install: `pip install -r requirements-dev.txt`
4. Commit both files

### Adding a New Module

1. Create module in `src/modules/`
2. Inherit from `BaseModule` in `src/modules/base.py`
3. Register in `src/modules/registry.py`
4. Add tests in `src/tests/`
5. Update documentation

### Debugging

- Use `print()` statements or logging
- Run with `--reload` flag for auto-restart on changes
- Check logs: `docker-compose logs -f webhook-1`
- Use pytest with `-v` for verbose output

## Troubleshooting

### Import Errors

- Ensure virtual environment is activated
- Run `pip install -r requirements-dev.txt`
- Check Python version: `python --version` (should be 3.9+)

### Test Failures

- Ensure Redis is running (for integration tests)
- Check environment variables are set correctly
- Run `make clean` and try again

### Docker Issues

- Ensure Docker is running
- Check `docker-compose ps` for service status
- View logs: `docker-compose logs`

## Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Pytest Documentation](https://docs.pytest.org/)
- [Python Virtual Environments](https://docs.python.org/3/tutorial/venv.html)

