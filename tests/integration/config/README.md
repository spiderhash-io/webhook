# Integration Test Configuration

This directory contains all configuration files needed for running integration tests.

## Files

- `docker-compose.yaml` - Docker Compose configuration for all services (Redis, RabbitMQ, ClickHouse, Redpanda, API server)
- `connections.json` - Connection configurations for all services (used by API server)
- `webhooks.json` - Webhook definitions for integration tests

## Usage

### Start Services

```bash
# From project root
cd tests/integration/config
docker compose up -d redis rabbitmq clickhouse redpanda api-server

# Or from project root using -f flag
docker compose -f tests/integration/config/docker-compose.yaml up -d
```

### Run Integration Tests

```bash
# From project root
pytest tests/integration/ -v -m integration
```

### Stop Services

```bash
cd tests/integration/config
docker compose down

# Or from project root
docker compose -f tests/integration/config/docker-compose.yaml down
```

## Configuration Details

### Services

- **Redis**: Port 6380 (external), 6379 (internal)
- **RabbitMQ**: Port 5672 (AMQP), 15672 (Management UI)
- **ClickHouse**: Port 8123 (HTTP), 9000 (Native)
- **Redpanda (Kafka)**: Port 19092 (Kafka)
- **API Server**: Port 8000

### Webhook Configurations

The `webhooks.json` file contains test webhooks:
- `integration_test_webhook` - Basic webhook with rate limiting
- `integration_test_webhook_clickhouse` - ClickHouse module
- `integration_test_webhook_rabbitmq` - RabbitMQ module
- `integration_test_webhook_redis_publish` - Redis publish module
- `integration_test_webhook_redis_rq` - Redis RQ module
- `integration_test_webhook_rate_limit` - Rate limiting test

### Connection Configurations

The `connections.json` file uses Docker service names:
- `rabbitmq_local` - Points to `rabbitmq` service
- `redis_local` - Points to `redis` service
- `clickhouse_local` - Points to `clickhouse` service

## Notes

- All configs in this directory are committed to version control
- These configs are specifically for integration tests
- Production configs should be in the project root or managed separately

