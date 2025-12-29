# Testing Guide

This document explains how to run tests for the core-webhook-module project.

## Quick Start

### Run All Tests (Excluding Long-Running)

```bash
cd /home/ubuntu/core-webhook-module
venv/bin/python -m pytest -v -m "not longrunning"
```

**Note**: Always use the virtual environment's Python (`venv/bin/python`) as pytest and other dependencies are installed there.

## Test Execution Commands

### Basic Test Execution

```bash
# Run all tests (excluding long-running tests)
venv/bin/python -m pytest -v -m "not longrunning"

# Run all tests including long-running (use with caution)
venv/bin/python -m pytest -v -m longrunning

# Run all tests without any marker filtering
venv/bin/python -m pytest -v
```

### Using Makefile (Alternative)

The project includes a Makefile with convenient test targets:

```bash
# Run unit tests (excludes integration and longrunning)
make test

# Run integration tests (requires Docker services)
make test-integration

# Run all tests (unit + integration, excludes longrunning)
make test-all

# Run long-running tests
make test-longrunning

# Run tests with coverage
make test-cov
```

## Test Configuration

### Pytest Configuration

The project uses `pytest.ini` for configuration:

- **Test paths**: `src/tests` (unit tests) and `tests/integration` (integration tests)
- **Test pattern**: Files matching `test_*.py`
- **Default markers**: Excludes `longrunning` tests by default
- **Async mode**: Auto (pytest-asyncio)

### Test Markers

Tests are categorized with markers:

- `unit`: Unit tests using mocks (fast, no external dependencies)
- `integration`: Integration tests requiring real services (Redis, RabbitMQ, ClickHouse, etc.)
- `performance`: Performance/load tests (slow, require running services)
- `slow`: Slow tests excluded by default
- `longrunning`: Long-running tests excluded by default

### Running Tests by Marker

```bash
# Run only unit tests
venv/bin/python -m pytest -v -m unit

# Run only integration tests
venv/bin/python -m pytest -v -m integration

# Run tests excluding integration
venv/bin/python -m pytest -v -m "not integration"

# Run tests excluding both integration and longrunning
venv/bin/python -m pytest -v -m "not integration and not longrunning"
```

## Test Results Interpretation

### Successful Test Run

A typical successful test run shows:

```
============================= test session starts ==============================
platform linux -- Python 3.12.3, pytest-9.0.1, pluggy-1.6.0
collected 2470 items / 109 deselected / 2361 selected

... (test output) ...

======== 2336 passed, 109 deselected, 161 warnings, 25 errors in 34.18s ========
```

**Key metrics:**
- **Passed**: Number of tests that passed
- **Deselected**: Tests excluded by markers/filters
- **Warnings**: Runtime warnings (usually non-critical, e.g., deprecation warnings)
- **Errors**: Tests that failed with errors (not just assertion failures)

### Common Warnings

You may see warnings like:

- **RuntimeWarning: coroutine was never awaited**: Usually indicates test mocking issues (non-critical for test execution)
- **DeprecationWarning**: Indicates use of deprecated APIs (should be addressed but doesn't fail tests)

### Test Failures

If tests fail, you'll see:

```
FAILED src/tests/test_example.py::TestExample::test_something
```

Check the detailed output for:
- **Assertion errors**: Expected vs actual values
- **Exception traces**: Stack traces showing where errors occurred
- **Error messages**: Specific failure reasons

## Test Output Management

### View Full Output

```bash
# Show all output (no truncation)
venv/bin/python -m pytest -v -m "not longrunning" -s

# Show last 100 lines of output
venv/bin/python -m pytest -v -m "not longrunning" 2>&1 | tail -100

# Show first 500 lines of output
venv/bin/python -m pytest -v -m "not longrunning" 2>&1 | head -500
```

### Save Test Results

```bash
# Save output to file
venv/bin/python -m pytest -v -m "not longrunning" > test_results.txt 2>&1

# Generate JUnit XML report
venv/bin/python -m pytest -v -m "not longrunning" --junitxml=test_results.xml
```

## Integration Tests

Integration tests require Docker services to be running:

```bash
# Start integration test services
make integration-up

# Run integration tests
make test-integration

# Stop integration test services
make integration-down

# View integration service logs
make integration-logs
```

## Troubleshooting

### Issue: `python: command not found`

**Solution**: Use `python3` or the venv Python:
```bash
venv/bin/python -m pytest
```

### Issue: `No module named pytest`

**Solution**: Ensure you're using the virtual environment:
```bash
# Activate venv first
source venv/bin/activate
python -m pytest

# Or use venv Python directly
venv/bin/python -m pytest
```

### Issue: Tests fail with connection errors

**Solution**: 
- For integration tests, ensure Docker services are running: `make integration-up`
- Check that required services (Redis, RabbitMQ, ClickHouse) are accessible

### Issue: Too many warnings

**Solution**: Suppress specific warnings:
```bash
venv/bin/python -m pytest -v -W ignore::RuntimeWarning
```

## Test Coverage

Generate coverage reports:

```bash
# Terminal coverage report
venv/bin/python -m pytest --cov=src --cov-report=term -m "not longrunning and not todo"

# HTML coverage report
venv/bin/python -m pytest --cov=src --cov-report=html -m "not longrunning and not todo"
# Then open htmlcov/index.html in a browser

# Both terminal and HTML reports
venv/bin/python -m pytest --cov=src --cov-report=html --cov-report=term -m "not longrunning and not todo"
```

## Running Specific Tests

```bash
# Run a specific test file
venv/bin/python -m pytest src/tests/test_webhook.py -v

# Run a specific test class
venv/bin/python -m pytest src/tests/test_webhook.py::TestWebhookHandler -v

# Run a specific test method
venv/bin/python -m pytest src/tests/test_webhook.py::TestWebhookHandler::test_something -v

# Run tests matching a pattern
venv/bin/python -m pytest -k "webhook" -v
```

## Performance Testing

For performance/load tests:

```bash
# Run performance tests (requires services)
venv/bin/python -m pytest -v -m performance

# Or use the Makefile
make test-longrunning
```

## Continuous Integration

For CI/CD pipelines, use:

```bash
# Fast feedback (unit tests only)
venv/bin/python -m pytest -v -m "unit and not longrunning" --tb=short

# Full test suite
venv/bin/python -m pytest -v -m "not longrunning" --junitxml=test_results.xml
```

## Best Practices

1. **Always use the virtual environment**: `venv/bin/python -m pytest`
2. **Exclude long-running tests by default**: Use `-m "not longrunning"`
3. **Check warnings**: Address deprecation warnings even if tests pass
4. **Run tests before committing**: Ensure all tests pass locally
5. **Use markers appropriately**: Tag tests correctly for easy filtering

## Test Statistics

As of the last test run:
- **Total tests**: ~2,470 collected
- **Selected tests**: ~2,361 (excluding longrunning)
- **Passing tests**: ~2,336
- **Test execution time**: ~34 seconds (for non-longrunning tests)

## Additional Resources

- **pytest.ini**: Main pytest configuration
- **Makefile**: Convenient test targets
- **conftest.py**: Shared test fixtures and configuration
- **DEVELOPMENT.md**: Development setup guide

