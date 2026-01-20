# Getting Started with Webhook Chaining

This guide will walk you through creating your first webhook chain step by step.

## Prerequisites

- Core Webhook Module installed and running
- Basic understanding of webhook configuration
- At least one module configured (e.g., `log`, `save_to_disk`)

## Step 1: Create a Simple Chain

Let's start with the simplest possible chain - logging and saving to disk:

```json
{
    "my_first_chain": {
        "data_type": "json",
        "chain": ["log", "save_to_disk"],
        "chain-config": {
            "execution": "sequential"
        },
        "authorization": "Bearer my_secret_token"
    }
}
```

This chain will:
1. Log the webhook payload to stdout
2. Save it to disk (default location)

## Step 2: Test Your Chain

Send a test webhook:

```bash
curl -X POST http://localhost:8000/webhook/my_first_chain \
  -H "Authorization: Bearer my_secret_token" \
  -H "Content-Type: application/json" \
  -d '{"event": "test", "data": "example"}'
```

You should see:
- Output in the console (from `log` module)
- A file saved to disk (from `save_to_disk` module)

## Step 3: Add Module Configuration

Now let's configure the `save_to_disk` module with a custom path:

```json
{
    "configured_chain": {
        "data_type": "json",
        "chain": [
            "log",
            {
                "module": "save_to_disk",
                "module-config": {
                    "path": "webhooks/my_chain"
                }
            }
        ],
        "chain-config": {
            "execution": "sequential"
        },
        "authorization": "Bearer my_secret_token"
    }
}
```

Notice how we can mix simple strings (`"log"`) with detailed objects for modules that need configuration.

## Step 4: Add a Connection

If you need to use a specific connection (e.g., for Redis, PostgreSQL, etc.):

```json
{
    "chain_with_connection": {
        "data_type": "json",
        "chain": [
            {
                "module": "redis_rq",
                "connection": "redis_local",
                "module-config": {
                    "queue_name": "my_queue"
                }
            },
            {
                "module": "log"
            }
        ],
        "chain-config": {
            "execution": "sequential"
        },
        "authorization": "Bearer my_secret_token"
    }
}
```

Make sure `redis_local` is defined in your `connections.json` file.

## Step 5: Choose Execution Mode

### Sequential (Default)

Use when modules depend on each other:

```json
{
    "sequential_chain": {
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

### Parallel

Use when modules are independent:

```json
{
    "parallel_chain": {
        "data_type": "json",
        "chain": ["s3", "redis_rq", "log"],
        "chain-config": {
            "execution": "parallel",
            "continue_on_error": true
        },
        "authorization": "Bearer token"
    }
}
```

## Step 6: Add Error Handling

Control what happens when a module fails:

```json
{
    "chain_with_error_handling": {
        "data_type": "json",
        "chain": ["s3", "redis_rq"],
        "chain-config": {
            "execution": "sequential",
            "continue_on_error": false  // Stop on first error
        },
        "authorization": "Bearer token"
    }
}
```

- `continue_on_error: true` (default): Continue even if a module fails
- `continue_on_error: false`: Stop chain execution on first error

## Common Patterns

### Pattern 1: Archive and Process

Save to S3 for archival, then queue for processing:

```json
{
    "archive_and_process": {
        "data_type": "json",
        "chain": [
            {
                "module": "s3",
                "connection": "s3_storage",
                "module-config": {
                    "bucket": "webhook-archive"
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
            "execution": "sequential"
        },
        "authorization": "Bearer secret"
    }
}
```

### Pattern 2: Fan-Out to Multiple Destinations

Send to multiple destinations simultaneously:

```json
{
    "fanout": {
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
                    "queue_name": "events"
                }
            },
            {
                "module": "log"
            }
        ],
        "chain-config": {
            "execution": "parallel"
        },
        "authorization": "Bearer secret"
    }
}
```

### Pattern 3: Log Everything

Always log webhooks while processing:

```json
{
    "logged_chain": {
        "data_type": "json",
        "chain": [
            "log",  // Log first
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

## Next Steps

- Learn about [advanced chaining features](webhook-chaining-advanced)
- Understand [error handling and troubleshooting](webhook-chaining-troubleshooting)
- Review the [full chaining reference](webhook-chaining)
