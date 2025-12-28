# Statistics

Tracks webhook usage statistics including requests per minute, hour, day, etc.

## Access Statistics

```bash
curl http://localhost:8000/stats
```

## Response Format

```json
{
    "webhook_id": {
        "total_requests": 1234,
        "requests_per_minute": 10,
        "requests_per_hour": 500,
        "requests_per_day": 10000,
        "last_request": "2024-01-15T10:30:00Z"
    }
}
```

## Statistics Tracking

Statistics are automatically tracked for:

- Total requests per webhook
- Requests per minute
- Requests per hour
- Requests per day
- Last request timestamp

## Storage

Statistics can be stored in:

- **In-memory** (default) - Lost on restart
- **Redis** - Persistent across restarts
- **ClickHouse** - Long-term analytics

## Features

- Real-time statistics
- Multiple time windows
- Per-webhook tracking
- Persistent storage options
- Low overhead

