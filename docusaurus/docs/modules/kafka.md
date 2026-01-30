# Kafka Module

The Kafka Module publishes webhook payloads to Apache Kafka topics.

## Configuration

```json
{
    "kafka_events": {
        "data_type": "json",
        "module": "kafka",
        "connection": "kafka_local",
        "module-config": {
            "topic": "webhook_events",
            "key": "event_key",
            "partition": 0,
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
        "bootstrap_servers": "localhost:9092"
    }
}
```

For multiple brokers:

```json
{
    "kafka_cluster": {
        "type": "kafka",
        "bootstrap_servers": "kafka1:9092,kafka2:9092,kafka3:9092"
    }
}
```

## Module Configuration Options

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `topic` | string | **Yes** | - | Kafka topic name |
| `key` | string | No | - | Message key for partitioning |
| `partition` | integer | No | - | Specific partition number |
| `forward_headers` | boolean | No | `false` | Include HTTP headers as Kafka headers |

## Topic Name Validation

Topic names are validated for security:

- Maximum 249 characters
- Allowed characters: `a-z`, `A-Z`, `0-9`, `_`, `-`, `.`
- Minimum 2 characters
- Cannot contain control characters or dangerous patterns

## Features

- High-throughput message publishing via aiokafka
- Message key support for partitioning
- Explicit partition selection
- HTTP header forwarding
- Topic name validation
- Error sanitization

## Example

### Basic Publishing

```json
{
    "events": {
        "data_type": "json",
        "module": "kafka",
        "connection": "kafka_prod",
        "module-config": {
            "topic": "events.incoming"
        },
        "authorization": "Bearer {$WEBHOOK_TOKEN}"
    }
}
```

### With Partitioning

```json
{
    "ordered_events": {
        "data_type": "json",
        "module": "kafka",
        "connection": "kafka_prod",
        "module-config": {
            "topic": "orders",
            "key": "order_id",
            "forward_headers": true
        },
        "authorization": "Bearer {$WEBHOOK_TOKEN}"
    }
}
```

### In a Chain

```json
{
    "multi_destination": {
        "data_type": "json",
        "chain": [
            {
                "module": "kafka",
                "connection": "kafka_prod",
                "module-config": {
                    "topic": "events.analytics"
                }
            },
            {
                "module": "postgresql",
                "connection": "postgres_local",
                "module-config": {
                    "table": "events"
                }
            }
        ],
        "chain-config": {
            "execution": "parallel"
        },
        "authorization": "Bearer token"
    }
}
```
