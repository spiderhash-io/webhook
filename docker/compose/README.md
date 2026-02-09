# Docker Compose Files

This directory contains Docker Compose configurations for different use cases. Each module has its own isolated setup with configuration files, environment variables, and test scripts.

## Available Compose Files

### Main Multi-Instance Setup
- **`docker-compose.yaml`** - Full multi-instance setup with 5 webhook instances, Redis, RabbitMQ, ClickHouse, Kafka (Redpanda), and analytics processor. Used for performance testing.

### Individual Module Testing

Each subdirectory contains a complete setup for testing individual modules with their required services:

**Core Modules (No External Services):**
- **`webhook-only/`** - Single webhook instance (for `log`, `save_to_disk`, `http_webhook`, `websocket`, `zeromq` modules)

**Database Modules:**
- **`postgres/`** - PostgreSQL module testing
- **`mysql/`** - MySQL/MariaDB module testing
- **`clickhouse/`** - ClickHouse module testing

**Message Queue Modules:**
- **`redis/`** - Redis module testing (`redis_rq`, `redis_publish`)
- **`rabbitmq/`** - RabbitMQ module testing
- **`kafka/`** - Kafka module testing (using Redpanda)
- **`activemq/`** - ActiveMQ module testing
- **`mqtt/`** - MQTT module testing

**Cloud Storage Modules:**
- **`s3/`** - S3 module testing (using MinIO)
- **`aws-sqs/`** - AWS SQS module testing (using LocalStack)
- **`gcp-pubsub/`** - GCP Pub/Sub module testing (using Pub/Sub Emulator)

**Infrastructure / Config Backends:**
- **`etcd/`** - etcd distributed config backend (replaces file-based config)
- **`vault/`** - HashiCorp Vault secret provider (resolves `{$vault:...}` references)

**Full Stack:**
- **`full-stack/`** - All services together (webhook + all dependencies)

## Module Directory Structure

Each module directory contains:
- **`docker-compose.yaml`** - Docker Compose configuration
- **`config/connections.json`** - Connection configuration for the module
- **`config/webhooks.json`** - Webhook definitions for testing
- **`env.example`** - Example environment variables (copy to `.env` to use)
- **`test.sh`** - Integration test script

## Usage

### Main Multi-Instance Setup
```bash
# From project root
cd docker/compose
docker compose -f docker-compose.yaml up -d
```

### Individual Module Testing

#### Quick Start (Recommended)
```bash
# Navigate to module directory
cd docker/compose/redis  # or any other module

# Copy environment file (if not already present)
cp env.example .env

# Start services
docker compose up -d

# Run integration test
./test.sh

# Stop services
docker compose down
```

#### Manual Setup
```bash
# Core modules (no external services)
cd docker/compose/webhook-only
docker compose up -d

# Database modules
cd docker/compose/postgres && docker compose up -d
cd docker/compose/mysql && docker compose up -d
cd docker/compose/clickhouse && docker compose up -d

# Message queue modules
cd docker/compose/redis && docker compose up -d
cd docker/compose/rabbitmq && docker compose up -d
cd docker/compose/kafka && docker compose up -d
cd docker/compose/activemq && docker compose up -d
cd docker/compose/mqtt && docker compose up -d

# Cloud storage modules
cd docker/compose/s3 && docker compose up -d
cd docker/compose/aws-sqs && docker compose up -d
cd docker/compose/gcp-pubsub && docker compose up -d

# Full stack (all services)
cd docker/compose/full-stack && docker compose up -d
```

### Running Tests

Each module includes a `test.sh` script that:
1. Starts the services (if not running)
2. Waits for services to be healthy
3. Sends test webhook requests
4. Verifies responses
5. Optionally tears down services

```bash
# Run test for a specific module
cd docker/compose/redis
./test.sh

# Test all modules (from project root)
for dir in docker/compose/*/; do
    if [ -f "$dir/test.sh" ]; then
        echo "Testing $(basename $dir)..."
        (cd "$dir" && ./test.sh)
    fi
done
```

### Stop Services
```bash
# Stop main setup
cd docker/compose
docker compose -f docker-compose.yaml down

# Stop individual module (from module directory)
cd docker/compose/redis
docker compose down

# Stop individual module (from project root)
docker compose -f docker/compose/redis/docker-compose.yaml down

# Stop all module services (from project root)
for dir in docker/compose/*/; do
    if [ -f "$dir/docker-compose.yaml" ]; then
        docker compose -f "$dir/docker-compose.yaml" down
    fi
done
```

## Configuration Files

Each module directory contains its own configuration files:

- **`config/connections.json`** - Connection configuration specific to the module
- **`config/webhooks.json`** - Webhook definitions for testing the module
- **`env.example`** - Example environment variables (documentation)

### Environment Variables

Each module uses a `.env` file (not committed to git) for environment-specific configuration:
- Copy `env.example` to `.env` in the module directory
- The `.env` file is automatically loaded by Docker Compose
- Example variables include service credentials, tokens, and file paths

**Note**: The `.env` files in `docker/compose/*/` directories are allowed to be committed (they serve as documentation), but production `.env` files should never be committed.

## Ports

Default ports used by services (each module uses port 8000 for webhook):

- **Webhook**: 8000 (single instance per module), 8000-8004 (multi-instance setup)
- **Redis**: 6379
- **RabbitMQ**: 5672 (AMQP), 15672 (Management UI)
- **ClickHouse**: 8123 (HTTP), 9000 (Native protocol - used by clickhouse-driver)
- **Kafka/Redpanda**: 19092 (external), 18081 (Schema Registry), 18082 (Pandaproxy)
- **PostgreSQL**: 5432
- **MySQL/MariaDB**: 3306
- **ActiveMQ**: 61616 (OpenWire), 61613 (STOMP), 8161 (Web Console)
- **MQTT**: 1883 (MQTT), 9001 (WebSockets)
- **MinIO (S3)**: 9000 (API), 9001 (Console)
- **LocalStack (AWS SQS)**: 4566 (Gateway), 4510-4559 (External services)
- **GCP Pub/Sub Emulator**: 8085
- **etcd**: 2379 (client API)
- **Vault**: 8200 (HTTP API + UI)

**Note**: Port conflicts may occur if multiple modules are running simultaneously. Each module is designed to run independently.

## Features

Each compose file includes:
- **Webhook service** - Built from local `docker/Dockerfile.smaller` (compact image)
- **Module-specific service** - The external service required by that module (if needed)
- **Health checks** - Ensures services are ready before webhook starts
- **Networking** - All services on the same `webhook-network` (isolated per module)
- **Volume mounts** - Source code (`src/`) and config files (`config/`) mounted for development
- **Environment variables** - Loaded from `.env` file (see `env.example` for documentation)
- **Test scripts** - Automated integration tests (`test.sh`) for each module

### Auto-Configuration Features

Some modules include automatic resource creation for easier testing:
- **GCP Pub/Sub**: Automatically creates topics if they don't exist
- **AWS SQS**: Automatically creates queues if they don't exist
- **RabbitMQ**: Automatically declares queues on first use

## Module Mapping

| Module | Compose Directory | External Service | Notes |
|--------|------------------|-----------------|-------|
| `log` | `webhook-only/` | None | Logs to stdout |
| `save_to_disk` | `webhook-only/` | None | Saves to local filesystem |
| `http_webhook` | `webhook-only/` | None | HTTP endpoint |
| `websocket` | `webhook-only/` | None | WebSocket endpoint |
| `zeromq` | `webhook-only/` | None | In-process ZeroMQ |
| `redis_rq` | `redis/` | Redis | Redis Queue |
| `redis_publish` | `redis/` | Redis | Redis Pub/Sub |
| `rabbitmq` | `rabbitmq/` | RabbitMQ | Auto-creates queues |
| `clickhouse` | `clickhouse/` | ClickHouse | Uses port 9000 (native) |
| `kafka` | `kafka/` | Redpanda | Kafka-compatible |
| `postgresql` / `postgres` | `postgres/` | PostgreSQL | |
| `mysql` / `mariadb` | `mysql/` | MariaDB | |
| `activemq` | `activemq/` | ActiveMQ Artemis | Default user: `artemis/artemis` |
| `mqtt` | `mqtt/` | Mosquitto | |
| `s3` | `s3/` | MinIO | S3-compatible storage |
| `aws_sqs` | `aws-sqs/` | LocalStack | Auto-creates queues |
| `gcp_pubsub` | `gcp-pubsub/` | Pub/Sub Emulator | Auto-creates topics |
| etcd backend | `etcd/` | etcd v3.5 | Distributed config (replaces JSON files) |
| Vault secrets | `vault/` | Vault 1.15 | Secret resolution (`{$vault:...}` syntax) |

## Troubleshooting

### Port Already in Use
If you get "port is already allocated" errors:
```bash
# Find process using port 8000
lsof -ti:8000 | xargs kill -9

# Or use a different port by modifying docker-compose.yaml
```

### Service Health Check Failures
- Wait longer for services to start (some services need 30-60 seconds)
- Check logs: `docker compose logs <service-name>`
- Verify health check commands are correct for the service version

### Configuration Errors
- Ensure `.env` file exists (copy from `env.example`)
- Verify `config/connections.json` and `config/webhooks.json` are valid JSON
- Check that connection credentials match the service configuration

### Module-Specific Issues

**ClickHouse**: Uses port 9000 (native protocol), not 8123 (HTTP)

**ActiveMQ**: Default credentials are `artemis/artemis`, not `admin/admin`

**AWS SQS**: LocalStack may need 60+ seconds to become healthy

**GCP Pub/Sub**: Topics are auto-created on first use (no manual setup needed)

**PostgreSQL/MySQL**: Health checks may need 30+ seconds on first startup

