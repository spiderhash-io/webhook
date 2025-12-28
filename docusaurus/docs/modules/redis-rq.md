# Redis RQ Module

The Redis RQ Module queues webhook payloads as jobs in Redis Queue for asynchronous processing.

## Configuration

```json
{
    "redis_rq_webhook": {
        "data_type": "json",
        "module": "redis_rq",
        "connection": "redis_local",
        "module-config": {
            "queue_name": "webhook_jobs"
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

- `queue_name`: Name of the Redis queue (required)
- `job_timeout`: Job timeout in seconds (default: 3600)
- `result_ttl`: Result TTL in seconds (default: 500)

## Features

- Asynchronous job processing
- Job result tracking
- Queue prioritization
- Connection pooling

