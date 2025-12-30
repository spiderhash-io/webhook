# Docker Compose Files

This directory contains Docker Compose configurations for different use cases.

## Available Compose Files

### Main Multi-Instance Setup
- **`docker-compose.yaml`** - Full multi-instance setup with 5 webhook instances, Redis, RabbitMQ, ClickHouse, Kafka (Redpanda), and analytics processor. Used for performance testing.

### Individual Service Testing

Each subdirectory contains a compose file for testing individual services:

- **`webhook-only/docker-compose.yaml`** - Single webhook instance
- **`redis/docker-compose.yaml`** - Redis only
- **`rabbitmq/docker-compose.yaml`** - RabbitMQ only
- **`clickhouse/docker-compose.yaml`** - ClickHouse only
- **`kafka/docker-compose.yaml`** - Kafka (Redpanda) only
- **`postgres/docker-compose.yaml`** - PostgreSQL only
- **`full-stack/docker-compose.yaml`** - All services together (webhook + all dependencies)

## Usage

### Main Multi-Instance Setup
```bash
# From project root
docker-compose -f docker/compose/docker-compose.yaml up -d
```

### Individual Services
```bash
# Start Redis only
docker-compose -f docker/compose/redis/docker-compose.yaml up -d

# Start RabbitMQ only
docker-compose -f docker/compose/rabbitmq/docker-compose.yaml up -d

# Start ClickHouse only
docker-compose -f docker/compose/clickhouse/docker-compose.yaml up -d

# Start Kafka only
docker-compose -f docker/compose/kafka/docker-compose.yaml up -d

# Start PostgreSQL only
docker-compose -f docker/compose/postgres/docker-compose.yaml up -d

# Start single webhook instance
docker-compose -f docker/compose/webhook-only/docker-compose.yaml up -d

# Start full stack
docker-compose -f docker/compose/full-stack/docker-compose.yaml up -d
```

### Stop Services
```bash
# Stop main setup
docker-compose -f docker/compose/docker-compose.yaml down

# Stop individual service (example: Redis)
docker-compose -f docker/compose/redis/docker-compose.yaml down
```

## Configuration Files

All compose files reference configuration files from:
- `config/development/` - Development configurations
- `config/examples/` - Example configurations

Make sure these directories contain the necessary `webhooks.json` and `connections.json` files.

## Ports

Default ports used by services:
- **Webhook**: 8000-8004 (multi-instance), 8000 (single)
- **Redis**: 6379
- **RabbitMQ**: 5672 (AMQP), 15672 (Management UI)
- **ClickHouse**: 8123 (HTTP), 9000 (Native)
- **Kafka**: 19092 (external)
- **PostgreSQL**: 5432

