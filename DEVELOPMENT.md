# Development Guide

This guide covers setting up and working with the development environment.

## Prerequisites

- Python 3.9 or higher
- pip (Python package manager)
- Git

## Initial Setup

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

## Development Workflow

### Running the Server

```bash
# Development mode with auto-reload
make run
# or
uvicorn src.main:app --reload --port 8000
```

### Running Tests

```bash
# Run all tests
make test
# or
pytest

# Run with coverage
make test-cov
# or
pytest --cov=src --cov-report=html --cov-report=term
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

## Docker Development

### Building Docker Image

```bash
make docker-build
# or
docker-compose build
```

### Running in Docker

```bash
make docker-up
# or
docker-compose up -d
```

### Viewing Logs

```bash
make docker-logs
# or
docker-compose logs -f
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

