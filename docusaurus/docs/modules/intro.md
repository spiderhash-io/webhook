---
description: "Overview of all 17 output modules available in Core Webhook Module for routing payloads to queues, databases, and APIs."
---

# Output Modules

The Core Webhook Module supports 17 different output modules for processing and forwarding webhook payloads. Each module can be configured independently and supports various connection types.

## Available Modules

- **[Log Module](./log.md)** - Output to stdout
- **[Save to Disk](./save-to-disk.md)** - Save webhooks to local filesystem
- **[RabbitMQ](./rabbitmq.md)** - Publish to RabbitMQ queues
- **[Redis RQ](./redis-rq.md)** - Queue jobs in Redis Queue
- **[Redis Publish](./redis-publish.md)** - Publish to Redis pub/sub channels
- **[HTTP Webhook](./http-webhook.md)** - Forward to HTTP endpoints
- **[Kafka](./kafka.md)** - Publish to Kafka topics
- **[MQTT](./mqtt.md)** - Publish to MQTT brokers
- **[WebSocket](./websocket.md)** - Forward to WebSocket connections
- **[ClickHouse](./clickhouse.md)** - Store in ClickHouse database
- **[PostgreSQL](./postgresql.md)** - Store in PostgreSQL database
- **[MySQL/MariaDB](./mysql.md)** - Store in MySQL/MariaDB database
- **[S3](./s3.md)** - Store in AWS S3
- **[AWS SQS](./aws-sqs.md)** - Send to AWS SQS queues
- **[GCP Pub/Sub](./gcp-pubsub.md)** - Publish to Google Cloud Pub/Sub
- **[ActiveMQ](./activemq.md)** - Publish to ActiveMQ
- **[ZeroMQ](./zeromq.md)** - Publish to ZeroMQ sockets

## Module Configuration

All modules follow a similar configuration pattern:

```json
{
    "webhook_id": {
        "data_type": "json",
        "module": "module_name",
        "connection": "connection_name",
        "module-config": {
            // Module-specific configuration
        }
    }
}
```

## Connection Management

Modules use connections defined in `connections.json`:

```json
{
    "connection_name": {
        "type": "module_type",
        "host": "localhost",
        "port": 5672,
        // Connection-specific settings
    }
}
```

## Using Modules in Chains

All modules can be used in [webhook chains](../features/webhook-chaining.md) to send payloads to multiple destinations:

```json
{
    "chained_webhook": {
        "data_type": "json",
        "chain": [
            "log",
            {
                "module": "s3",
                "connection": "s3_storage",
                "module-config": {
                    "bucket": "webhooks"
                }
            },
            {
                "module": "redis_rq",
                "connection": "redis_local",
                "module-config": {
                    "queue_name": "events"
                }
            }
        ],
        "chain-config": {
            "execution": "sequential"
        },
        "authorization": "Bearer secret"
    }
}
```

See the [Webhook Chaining documentation](../features/webhook-chaining.md) for more details.

