# RabbitMQ Module

The RabbitMQ Module publishes webhook payloads to RabbitMQ message queues.

## Configuration

```json
{
    "rabbitmq_webhook": {
        "data_type": "json",
        "module": "rabbitmq",
        "connection": "rabbitmq_local",
        "module-config": {
            "queue_name": "webhook_events"
        },
        "authorization": "Bearer token"
    }
}
```

## Connection Configuration

In `connections.json`:

```json
{
    "rabbitmq_local": {
        "type": "rabbitmq",
        "host": "localhost",
        "port": 5672,
        "user": "guest",
        "pass": "guest",
        "vhost": "/"
    }
}
```

## Module Configuration Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `queue_name` | string | Yes | Name of the RabbitMQ queue |

:::info Queue Behavior
Queues are automatically declared as **durable** (survives broker restart) with `delivery_mode=2` (persistent messages). Exchange and routing key configuration is not currently supported - messages are published directly to the queue via the default exchange.
:::

## Queue Name Validation

Queue names are validated for security:

- Maximum 255 characters
- Allowed characters: `a-z`, `A-Z`, `0-9`, `_`, `-`, `.`, `:`
- Cannot start with `amq.` (reserved for system queues)
- Cannot contain path traversal sequences or control characters

## Features

- Reliable message delivery with persistent messages
- Durable queue declaration
- Connection pooling for performance
- Automatic reconnection handling
- Error sanitization (RabbitMQ details not exposed to clients)

## Example

### Basic Queue Publishing

```json
{
    "order_events": {
        "data_type": "json",
        "module": "rabbitmq",
        "connection": "rabbitmq_prod",
        "module-config": {
            "queue_name": "orders.incoming"
        },
        "authorization": "Bearer {$ORDER_WEBHOOK_TOKEN}"
    }
}
```

### With Webhook Chaining

```json
{
    "multi_destination": {
        "data_type": "json",
        "chain": [
            {
                "module": "rabbitmq",
                "connection": "rabbitmq_prod",
                "module-config": {
                    "queue_name": "events.primary"
                }
            },
            {
                "module": "log"
            }
        ],
        "chain-config": {
            "execution": "parallel"
        },
        "authorization": "Bearer token"
    }
}
```
