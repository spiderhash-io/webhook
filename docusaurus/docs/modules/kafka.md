# Kafka Module

The Kafka Module publishes webhook payloads to Apache Kafka topics.

## Configuration

```json
{
    "kafka_events": {
        "data_type": "json",
        "module": "kafka",
        "topic": "webhook_events",
        "connection": "kafka_local",
        "module-config": {
            "key": "event_key",
            "forward_headers": true
        },
        "authorization": "Bearer kafka_secret"
    }
}
```

## Connection Configuration

In `connections.json`:

```json
{
    "kafka_local": {
        "type": "kafka",
        "bootstrap_servers": "localhost:9092",
        "security_protocol": "PLAINTEXT",
        "sasl_mechanism": "PLAIN",
        "sasl_username": "user",
        "sasl_password": "pass"
    }
}
```

## Module Configuration Options

- `key`: Optional message key for partitioning
- `forward_headers`: Whether to include HTTP headers in the message (default: false)
- `partition`: Optional partition number
- `compression_type`: Compression type (none, gzip, snappy, lz4, zstd)

## Features

- High-throughput message publishing
- Partitioning support
- Compression options
- SASL authentication support
- Connection pooling

