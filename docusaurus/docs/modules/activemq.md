# ActiveMQ Module

The ActiveMQ Module publishes webhook payloads to Apache ActiveMQ message brokers.

## Configuration

```json
{
    "activemq_webhook": {
        "data_type": "json",
        "module": "activemq",
        "connection": "activemq_local",
        "module-config": {
            "destination": "webhook.events",
            "destination_type": "queue"
        },
        "authorization": "Bearer token"
    }
}
```

## Connection Configuration

In `connections.json`:

```json
{
    "activemq_local": {
        "type": "activemq",
        "host": "localhost",
        "port": 61613,
        "username": "admin",
        "password": "admin",
        "use_ssl": false
    }
}
```

## Module Configuration Options

- `destination`: Queue or topic name (required)
- `destination_type`: "queue" or "topic" (default: "queue")
- `persistent`: Whether messages should be persistent (default: true)

## Features

- Queue and topic support
- Persistent messages
- SSL/TLS support
- Connection pooling
- STOMP protocol support

