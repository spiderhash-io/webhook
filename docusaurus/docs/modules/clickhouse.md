# ClickHouse Module

The ClickHouse Module stores webhook payloads in ClickHouse database for analytics and monitoring.

## Configuration

```json
{
    "clickhouse_webhook": {
        "data_type": "json",
        "module": "clickhouse",
        "connection": "clickhouse_local",
        "module-config": {
            "table": "webhook_logs",
            "include_headers": true,
            "include_timestamp": true
        },
        "authorization": "Bearer clickhouse_secret"
    }
}
```

## Connection Configuration

In `connections.json`:

```json
{
    "clickhouse_local": {
        "type": "clickhouse",
        "host": "localhost",
        "port": 8123,
        "database": "webhooks",
        "user": "default",
        "password": "",
        "secure": false
    }
}
```

## Module Configuration Options

- `table`: ClickHouse table name (required)
- `include_headers`: Whether to include HTTP headers (default: false)
- `include_timestamp`: Whether to include timestamp column (default: true)
- `engine`: Table engine (default: "MergeTree")

## Features

- High-performance analytics storage
- Automatic table creation
- Columnar storage optimization
- Time-series data support
- Connection pooling

