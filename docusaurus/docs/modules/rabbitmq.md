# RabbitMQ Module

The RabbitMQ Module publishes webhook payloads to RabbitMQ message queues.

## Configuration

```json
{
    "rabbitmq_webhook": {
        "data_type": "json",
        "module": "rabbitmq",
        "queue_name": "webhook_events",
        "connection": "rabbitmq_local",
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

- `queue_name`: Name of the RabbitMQ queue (required)
- `exchange`: Optional exchange name
- `routing_key`: Optional routing key
- `durable`: Whether the queue should be durable (default: true)
- `exclusive`: Whether the queue should be exclusive (default: false)
- `auto_delete`: Whether the queue should auto-delete (default: false)

## Features

- Reliable message delivery
- Queue persistence
- Exchange and routing key support
- Connection pooling for performance

