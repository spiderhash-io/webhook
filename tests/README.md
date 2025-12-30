# Tests

This directory contains all tests for the webhook module.

## Directory Structure

- **`unit/`** - Unit tests
  - Fast, isolated tests using mocks
  - No external dependencies required
  - Run with: `pytest tests/unit/`

- **`integration/`** - Integration/E2E tests
  - Tests that require real services (Redis, RabbitMQ, ClickHouse, etc.)
  - Requires Docker services to be running
  - Run with: `pytest tests/integration/` (after starting services)

## Running Tests

### Unit Tests Only
```bash
make test
# or
pytest tests/unit/ -v
```

### Integration Tests Only
```bash
# Start integration services first
make integration-up

# Run integration tests
make test-integration
# or
pytest tests/integration/ -v -m integration
```

### All Tests
```bash
make test-all
# or
pytest tests/ -v -m "not longrunning"
```

### With Coverage
```bash
make test-cov
# or
pytest --cov=src --cov-report=html tests/
```

## Test Markers

Tests are marked with pytest markers:
- `@pytest.mark.unit` - Unit tests
- `@pytest.mark.integration` - Integration tests
- `@pytest.mark.longrunning` - Long-running tests (excluded by default)
- `@pytest.mark.performance` - Performance tests
- `@pytest.mark.todo` - Tests that need fixing (excluded by default)

## Test Organization

### Unit Tests (`tests/unit/`)
- Test individual components in isolation
- Use mocks for external dependencies
- Fast execution
- Examples: `test_webhook_flow.py`, `test_basic_auth.py`, `test_chain_processor.py`

### Integration Tests (`tests/integration/`)
- Test full workflows with real services
- Require Docker services to be running
- Slower execution
- Organized by feature:
  - `api/` - API endpoint tests
  - `modules/` - Module integration tests
  - `config/` - Configuration and docker-compose for integration tests

## Performance Tests

Performance tests are located in `tests/unit/`:
- `performance_test_single.py` - Single instance performance test
- `performance_test_multi_instance.py` - Multi-instance performance test
- `performance_test_redis.py` - Redis-specific performance test

Run performance tests with:
```bash
./scripts/run_performance_test.sh
```

