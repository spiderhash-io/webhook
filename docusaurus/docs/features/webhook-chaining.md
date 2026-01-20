# Webhook Chaining

Send webhook payloads to multiple destinations in sequence or parallel. This feature allows you to create complex workflows where a single webhook triggers multiple actions.

## Overview

Webhook chaining enables you to send a single webhook payload to multiple destinations, either sequentially (one after another) or in parallel (all at once). This is useful for scenarios like:

- **Data Pipeline**: Save to database, then publish to message queue
- **Multi-Destination**: Archive to S3 while also processing via Redis
- **Workflow Orchestration**: Transform data, validate, then forward to multiple services

## Quick Start

### Simple Array Format

The simplest way to create a chain is using an array of module names:

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

This will execute `s3` first, then `redis_rq`, using default configurations for each module.

### Detailed Format with Per-Module Config

For more control, use detailed module configurations:

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

## Configuration Reference

### Chain Items

Each item in the `chain` array can be:

1. **String** (simple format): Just the module name
   ```json
   "chain": ["s3", "redis_rq"]
   ```

2. **Object** (detailed format): Full configuration per module
   ```json
   "chain": [
       {
           "module": "s3",
           "connection": "s3_storage",
           "module-config": { ... },
           "retry": { ... }
       }
   ]
   ```

### Chain Item Fields

- **`module`** (required): Module name (e.g., `"s3"`, `"redis_rq"`, `"postgresql"`)
- **`connection`** (optional): Connection name from `connections.json`
- **`module-config`** (optional): Module-specific configuration (same as top-level `module-config`)
- **`retry`** (optional): Per-module retry configuration
  ```json
  "retry": {
      "enabled": true,
      "max_attempts": 3,
      "initial_delay": 1.0,
      "max_delay": 60.0,
      "backoff_multiplier": 2.0
  }
  ```

### Chain Configuration

The `chain-config` object controls how the chain executes:

- **`execution`** (optional, default: `"sequential"`): 
  - `"sequential"`: Execute modules one after another
  - `"parallel"`: Execute all modules simultaneously
  
- **`continue_on_error`** (optional, default: `true`):
  - `true`: Continue executing remaining modules even if one fails
  - `false`: Stop chain execution on first error (sequential mode only)

## Execution Modes

### Sequential Execution

Modules execute one after another in order. The next module starts only after the previous one completes (or fails if `continue_on_error` is `false`).

**Use cases:**
- Dependent operations (save to DB, then publish to Kafka)
- Data transformation pipeline
- Ordered processing requirements

**Performance:** Total latency = sum of all module latencies

```json
{
    "chain-config": {
        "execution": "sequential",
        "continue_on_error": true
    }
}
```

### Parallel Execution

All modules execute simultaneously using `asyncio.gather`. All modules start at the same time and execute independently.

**Use cases:**
- Independent operations (save to S3 and Redis simultaneously)
- Fan-out to multiple destinations
- Performance optimization when modules don't depend on each other

**Performance:** Total latency = slowest module latency

```json
{
    "chain-config": {
        "execution": "parallel",
        "continue_on_error": true
    }
}
```

**Note:** `continue_on_error` always applies in parallel mode - all modules will attempt execution regardless of failures.

## Examples

### Example 1: Archive then Process (Sequential)

Save webhook to S3 for archival, then queue for processing:

```json
{
    "archive_and_process": {
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

### Example 2: Multi-Destination Fan-Out (Parallel)

Save to database and publish to RabbitMQ simultaneously:

```json
{
    "fanout_webhook": {
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
            },
            {
                "module": "log"
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

### Example 3: Chain with Retries

Each module can have its own retry configuration:

```json
{
    "reliable_chain": {
        "data_type": "json",
        "chain": [
            {
                "module": "s3",
                "connection": "s3_storage",
                "module-config": {
                    "bucket": "webhooks"
                },
                "retry": {
                    "enabled": true,
                    "max_attempts": 5,
                    "initial_delay": 1.0,
                    "max_delay": 30.0
                }
            },
            {
                "module": "http_webhook",
                "module-config": {
                    "url": "https://api.example.com/webhooks",
                    "method": "POST"
                },
                "retry": {
                    "enabled": true,
                    "max_attempts": 3
                }
            }
        ],
        "chain-config": {
            "execution": "sequential",
            "continue_on_error": false
        },
        "authorization": "Bearer secret"
    }
}
```

### Example 4: Simple Array Format

For basic use cases, use the simple array format:

```json
{
    "simple_chain": {
        "data_type": "json",
        "chain": ["log", "save_to_disk"],
        "chain-config": {
            "execution": "sequential"
        },
        "authorization": "Bearer token"
    }
}
```

## Error Handling

### Continue on Error (Default: `true`)

When `continue_on_error` is `true`:
- Failed modules are logged but don't stop the chain
- Remaining modules continue execution
- Useful for best-effort delivery to multiple destinations

When `continue_on_error` is `false` (sequential only):
- Chain stops at first failure
- Remaining modules are marked as not executed
- Useful when later modules depend on earlier ones succeeding

### Error Logging

Chain execution results are logged with details:
- Success/failure status for each module
- Error messages for failed modules
- Summary statistics (total, successful, failed)

Example log output:
```
Chain execution for webhook 'my_webhook': 2/3 modules succeeded, 1 failed
  - Module 's3' succeeded
  - Module 'redis_rq' failed: Connection timeout
  - Module 'log' succeeded
```

## Security Features

### Chain Length Limits

- **Maximum chain length**: 20 modules (prevents DoS attacks)
- **Minimum chain length**: 1 module
- Validation occurs before chain execution

### Input Validation

- Module name validation (must exist in ModuleRegistry)
- Type validation for all configuration fields
- Rejection of unknown fields to prevent injection
- Configuration structure validation

### Resource Management

- Concurrency limits via TaskManager (default: 100 concurrent tasks)
- Proper resource cleanup (module teardown) after execution
- Memory-safe deep copying with fallback to shallow copy
- Error sanitization to prevent information disclosure

## Performance Considerations

### Sequential Chains

- **Latency**: Sum of all module latencies
- **Example**: S3 (200ms) + Redis (50ms) = 250ms total
- **Use when**: Modules depend on each other or order matters

### Parallel Chains

- **Latency**: Slowest module latency
- **Example**: S3 (200ms) + Redis (50ms) = 200ms total
- **Use when**: Modules are independent
- **Resource usage**: Each module creates a task (limited by TaskManager)

### Best Practices

- Use sequential for dependent operations
- Use parallel for independent operations
- Monitor task manager metrics with parallel chains
- Consider payload size (large payloads × many modules = high memory usage)
- Recommended chain length: 5-10 modules for sequential, limited by task manager for parallel

## Backward Compatibility

The `module` field still works for single destinations. If both `module` and `chain` are present, `chain` takes precedence.

```json
{
    "legacy_webhook": {
        "module": "log"  // Still works!
    },
    "new_webhook": {
        "chain": ["log", "s3"]  // Chain takes precedence
    }
}
```

## Related Documentation

- [Getting Started with Chaining](webhook-chaining-getting-started) - Step-by-step guide
- [Advanced Chaining](webhook-chaining-advanced) - Per-module configs, retries, and best practices
- [Chaining Troubleshooting](webhook-chaining-troubleshooting) - Common issues and solutions

