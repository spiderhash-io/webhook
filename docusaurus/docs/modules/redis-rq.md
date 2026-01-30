# Redis RQ Module

The Redis RQ Module queues webhook payloads as jobs in Redis Queue (RQ) for asynchronous processing by worker processes.

## Configuration

```json
{
    "redis_rq_webhook": {
        "data_type": "json",
        "module": "redis_rq",
        "connection": "redis_local",
        "module-config": {
            "queue_name": "webhook_jobs",
            "function": "myapp.tasks.process_webhook"
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
        "type": "redis-rq",
        "host": "localhost",
        "port": 6379,
        "db": 0,
        "password": null
    }
}
```

## Module Configuration Options

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `function` | string | **Yes** | - | Python function path to execute (e.g., `"myapp.tasks.process_webhook"`) |
| `queue_name` | string | No | `"default"` | Name of the Redis queue |

:::warning Required Configuration
The `function` option is **required**. It specifies the Python function that RQ workers will execute to process the webhook payload. The function receives `(payload, headers)` as arguments.
:::

## Function Name Validation

Function names are validated for security to prevent code injection:

**Allowed formats:**
- Simple function name: `process_data`
- Module.function: `utils.process`
- Package.module.function: `myapp.tasks.process_webhook`

**Blocked patterns:**
- System modules: `os.*`, `subprocess.*`
- Dangerous builtins: `eval`, `exec`, `compile`, `__import__`
- Magic methods: `__*__`

## Worker Setup

You need RQ workers running to process queued jobs:

```bash
# Start a worker for the webhook_jobs queue
rq worker webhook_jobs --url redis://localhost:6379/0
```

Example worker function:

```python
# myapp/tasks.py
def process_webhook(payload: dict, headers: dict):
    """Process incoming webhook payload."""
    print(f"Processing webhook: {payload}")
    # Your processing logic here
    return {"status": "processed"}
```

## Features

- Asynchronous job processing via RQ workers
- Function name validation (prevents code injection)
- Connection pooling
- Error sanitization

## Example

### Basic Job Queuing

```json
{
    "async_processor": {
        "data_type": "json",
        "module": "redis_rq",
        "connection": "redis_prod",
        "module-config": {
            "queue_name": "high_priority",
            "function": "webhooks.handlers.process_payment"
        },
        "authorization": "Bearer {$PAYMENT_TOKEN}"
    }
}
```

### With Webhook Chaining

Queue for async processing after saving to database:

```json
{
    "save_and_process": {
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
                "module": "redis_rq",
                "connection": "redis_local",
                "module-config": {
                    "queue_name": "process_events",
                    "function": "workers.process_event"
                }
            }
        ],
        "chain-config": {
            "execution": "sequential"
        },
        "authorization": "Bearer token"
    }
}
```
