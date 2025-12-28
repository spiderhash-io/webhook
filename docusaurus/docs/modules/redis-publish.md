# Redis Publish Module

The Redis Publish Module publishes webhook payloads to Redis pub/sub channels.

## Configuration

```json
{
    "redis_pub_webhook": {
        "data_type": "json",
        "module": "redis_publish",
        "connection": "redis_local",
        "module-config": {
            "channel": "webhook_events"
        },
        "authorization": "Bearer token"
    }
}
```

## Connection Configuration

In `connections.json`:

```json
{
    "redis_local": {
        "type": "redis-publish",
        "host": "localhost",
        "port": 6379,
        "db": 0,
        "password": null
    }
}
```

## Module Configuration Options

- `channel`: Redis pub/sub channel name (required)
- `format`: Message format - "json" or "raw" (default: "json")

## Features

- Real-time pub/sub messaging
- Multiple subscribers support
- Connection pooling
- JSON and raw message formats

