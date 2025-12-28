# Webhook Chaining

Send webhook payloads to multiple destinations in sequence or parallel. This feature allows you to create complex workflows where a single webhook triggers multiple actions.

## Simple Array Format

```json
{
    "chained_webhook": {
        "data_type": "json",
        "chain": ["s3", "redis_rq"],
        "chain-config": {
            "execution": "sequential",
            "continue_on_error": true
        },
        "authorization": "Bearer token"
    }
}
```

## Detailed Format with Per-Module Config

```json
{
    "chained_webhook": {
        "data_type": "json",
        "chain": [
            {
                "module": "s3",
                "connection": "s3_storage",
                "module-config": {
                    "bucket": "webhook-archive",
                    "prefix": "events"
                },
                "retry": {
                    "enabled": true,
                    "max_attempts": 3
                }
            },
            {
                "module": "redis_rq",
                "connection": "redis_local",
                "module-config": {
                    "queue_name": "process_events"
                }
            }
        ],
        "chain-config": {
            "execution": "sequential",
            "continue_on_error": true
        },
        "authorization": "Bearer secret"
    }
}
```

## Configuration Options

- `chain`: Array of module names (strings) or detailed module configurations (objects)
- `chain-config.execution`: `"sequential"` (one after another) or `"parallel"` (all at once)
- `chain-config.continue_on_error`: `true` to continue chain execution even if a module fails, `false` to stop on first error
- `retry`: Per-module retry configuration (optional)

## Execution Modes

### Sequential

Modules execute one after another in order. Useful when one module depends on another (e.g., save to DB then publish to Kafka).

```json
{
    "chain-config": {
        "execution": "sequential",
        "continue_on_error": true
    }
}
```

### Parallel

All modules execute simultaneously. Useful for independent operations (e.g., save to DB and send to RabbitMQ at the same time).

```json
{
    "chain-config": {
        "execution": "parallel",
        "continue_on_error": true
    }
}
```

## Examples

### Example 1: Save to S3 then Redis (Sequential)

```json
{
    "s3_then_redis": {
        "data_type": "json",
        "chain": [
            {
                "module": "s3",
                "connection": "s3_storage",
                "module-config": {
                    "bucket": "webhook-archive",
                    "prefix": "events"
                }
            },
            {
                "module": "redis_rq",
                "connection": "redis_local",
                "module-config": {
                    "queue_name": "process_events"
                }
            }
        ],
        "chain-config": {
            "execution": "sequential",
            "continue_on_error": true
        },
        "authorization": "Bearer secret"
    }
}
```

### Example 2: Save to DB and RabbitMQ (Parallel)

```json
{
    "db_and_rmq": {
        "data_type": "json",
        "chain": [
            {
                "module": "postgresql",
                "connection": "postgres_local",
                "module-config": {
                    "table": "webhook_events"
                }
            },
            {
                "module": "rabbitmq",
                "connection": "rabbitmq_local",
                "module-config": {
                    "queue_name": "event_queue"
                }
            }
        ],
        "chain-config": {
            "execution": "parallel",
            "continue_on_error": true
        },
        "authorization": "Bearer secret"
    }
}
```

## Security Features

- Maximum chain length limit (20 modules) to prevent DoS attacks
- Module name validation to prevent injection attacks
- Type validation for all configuration fields
- Resource management with concurrency limits
- Error sanitization to prevent information disclosure

