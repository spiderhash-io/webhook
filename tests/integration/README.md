# Integration Tests

This directory contains integration tests that run against real services (Redis, RabbitMQ, ClickHouse) and make actual HTTP calls to a running FastAPI server.

## Differences from Unit Tests

- **Unit tests** (`src/tests/`): Use mocks, ASGITransport, in-process testing
- **Integration tests** (`tests/integration/`): Real HTTP calls, real services, actual data persistence

## Prerequisites

Before running integration tests, you must have:

1. **Docker services running** (includes API server):
   ```bash
   # Using Makefile (recommended)
   make integration-up
   
   # Or manually
   cd tests/integration/config
   docker compose up -d redis rabbitmq clickhouse redpanda api-server
   ```

   All configuration files are in `tests/integration/config/`:
   - `docker-compose.yaml` - Service definitions
   - `connections.json` - Service connection configs
   - `webhooks.json` - Test webhook definitions

## Running Integration Tests

### Run all integration tests:
```bash
pytest tests/integration/ -v -m integration
```

### Run specific test categories:
```bash
# API endpoint tests
pytest tests/integration/api/ -v -m integration

# Module integration tests
pytest tests/integration/modules/ -v -m integration
```

### Run with Makefile:
```bash
# Start services
make integration-up

# Run tests
make test-integration

# Stop services
make integration-down

# View logs
make integration-logs
```

## Test Structure

```
tests/integration/
├── __init__.py
├── conftest.py          # Shared fixtures and configuration
├── utils.py             # Helper utilities
├── test_config.py       # Test configuration (ports, URLs, etc.)
├── README.md            # This file
├── api/                 # API endpoint tests
│   ├── __init__.py
│   └── test_webhook_endpoints.py
└── modules/             # Module integration tests
    ├── __init__.py
    ├── test_redis_integration.py
    ├── test_redis_rq_integration.py
    ├── test_redis_stats_buckets_integration.py
    ├── test_redis_publish_advanced_integration.py
    ├── test_rabbitmq_integration.py
    ├── test_rabbitmq_pool_integration.py
    ├── test_rabbitmq_advanced_integration.py
    ├── test_clickhouse_integration.py
    ├── test_clickhouse_advanced_integration.py
    ├── test_clickhouse_analytics_integration.py
    ├── test_rate_limiter_integration.py
    ├── test_retry_handler_integration.py
    ├── test_websocket_integration.py
    ├── test_http_webhook_advanced_integration.py
    ├── test_save_to_disk_advanced_integration.py
    ├── test_multi_module_integration.py
    ├── test_analytics_processor_integration.py
    ├── test_kafka_integration.py
    └── test_s3_integration.py
└── api/                 # API endpoint tests
    ├── __init__.py
    ├── test_webhook_endpoints.py
    ├── test_end_to_end_webhook_flow.py
    ├── test_authentication_integration.py
    ├── test_validation_integration.py
    ├── test_cors_integration.py
    └── test_error_handling_integration.py
```

## Test Configuration

Test configuration is defined in `test_config.py` and can be overridden with environment variables:

- `REDIS_HOST` (default: localhost)
- `REDIS_PORT` (default: 6380)
- `RABBITMQ_HOST` (default: localhost)
- `RABBITMQ_PORT` (default: 5672)
- `CLICKHOUSE_HOST` (default: localhost)
- `CLICKHOUSE_PORT` (default: 8123)
- `KAFKA_HOST` (default: localhost)
- `KAFKA_PORT` (default: 19092)
- `API_BASE_URL` (default: http://localhost:8000)

## Fixtures

The `conftest.py` file provides several fixtures:

- `docker_services_available`: Checks if Docker services are running
- `services_ready`: Waits for services to be healthy
- `api_server_ready`: Checks if FastAPI server is running
- `http_client`: httpx AsyncClient for making HTTP requests
- `authenticated_client`: httpx client with authentication headers
- `cleanup_test_data`: Automatically cleans up test data before/after tests

## Writing New Integration Tests

### Example: API Endpoint Test

```python
import pytest
from tests.integration.utils import make_authenticated_request

@pytest.mark.integration
class TestMyEndpoint:
    @pytest.mark.asyncio
    async def test_my_endpoint(self, http_client, test_auth_token):
        response = await make_authenticated_request(
            http_client,
            "POST",
            "/webhook/my_webhook",
            auth_token=test_auth_token,
            json={"test": "data"}
        )
        assert response.status_code == 200
```

### Example: Module Integration Test

```python
import pytest
import redis.asyncio as redis
from tests.integration.test_config import REDIS_URL

@pytest.mark.integration
class TestMyModule:
    @pytest.fixture
    async def redis_client(self):
        r = redis.from_url(REDIS_URL, decode_responses=True)
        yield r
        await r.aclose()
    
    @pytest.mark.asyncio
    async def test_module_integration(self, redis_client):
        # Test actual module behavior
        await redis_client.set("test_key", "test_value")
        value = await redis_client.get("test_key")
        assert value == "test_value"
```

## Troubleshooting

### Services not available

If tests are skipped with "Docker services not available":

1. Check services are running:
   ```bash
   docker-compose ps
   ```

2. Start services:
   ```bash
   docker compose up -d redis rabbitmq clickhouse redpanda
   ```

3. Wait for services to be healthy:
   ```bash
   docker-compose ps  # Check all services show "healthy"
   ```

### API server not available

If tests are skipped with "FastAPI server not available":

1. Start the server:
   ```bash
   uvicorn src.main:app --port 8000
   ```

2. Or use Makefile:
   ```bash
   make run
   ```

### Test failures

- Check service logs: `docker-compose logs redis rabbitmq clickhouse`
- Verify webhook configuration in `webhooks.json`
- Check connection configuration in `connections.json`
- Ensure test webhook IDs match your configuration

## Cleanup

Integration tests automatically clean up test data using the `cleanup_test_data` fixture. Test data is prefixed with `test:integration:` for Redis keys and `test_integration_` for RabbitMQ queues.

To manually clean up:

```bash
# Clean Redis test keys
redis-cli --port 6380 KEYS "test:integration:*" | xargs redis-cli --port 6380 DEL

# Clean RabbitMQ test queues (via management UI or CLI)
```

## Notes

- Integration tests are slower than unit tests because they interact with real services
- Tests may be skipped if services are not available (this is expected behavior)
- Some tests require specific webhook configurations in `webhooks.json`
- Test data is automatically cleaned up, but manual cleanup may be needed in case of test failures

