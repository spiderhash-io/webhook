# Output Modules

The Core Webhook Module supports 17 different output modules for processing and forwarding webhook payloads. Each module can be configured independently and supports various connection types.

## Available Modules

- **[Log Module](log)** - Output to stdout
- **[Save to Disk](save-to-disk)** - Save webhooks to local filesystem
- **[RabbitMQ](rabbitmq)** - Publish to RabbitMQ queues
- **[Redis RQ](redis-rq)** - Queue jobs in Redis Queue
- **[Redis Publish](redis-publish)** - Publish to Redis pub/sub channels
- **[HTTP Webhook](http-webhook)** - Forward to HTTP endpoints
- **[Kafka](kafka)** - Publish to Kafka topics
- **[MQTT](mqtt)** - Publish to MQTT brokers
- **[WebSocket](websocket)** - Forward to WebSocket connections
- **[ClickHouse](clickhouse)** - Store in ClickHouse database
- **[PostgreSQL](postgresql)** - Store in PostgreSQL database
- **[MySQL/MariaDB](mysql)** - Store in MySQL/MariaDB database
- **[S3](s3)** - Store in AWS S3
- **[AWS SQS](aws-sqs)** - Send to AWS SQS queues
- **[GCP Pub/Sub](gcp-pubsub)** - Publish to Google Cloud Pub/Sub
- **[ActiveMQ](activemq)** - Publish to ActiveMQ
- **[ZeroMQ](zeromq)** - Publish to ZeroMQ sockets

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

All modules can be used in [webhook chains](../features/webhook-chaining) to send payloads to multiple destinations:

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

See the [Webhook Chaining documentation](../features/webhook-chaining) for more details.

