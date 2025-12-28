# PostgreSQL Module

The PostgreSQL Module stores webhook payloads in PostgreSQL databases with support for JSONB, relational, or hybrid storage modes.

## Configuration

```json
{
    "postgres_webhook": {
        "data_type": "json",
        "module": "postgresql",
        "connection": "postgres_local",
        "module-config": {
            "table": "webhook_events",
            "storage_mode": "json",
            "upsert": true,
            "upsert_key": "event_id",
            "include_headers": true
        },
        "authorization": "Bearer db_secret"
    }
}
```

## Connection Configuration

In `connections.json`:

```json
{
    "postgres_local": {
        "type": "postgresql",
        "host": "localhost",
        "port": 5432,
        "database": "webhooks",
        "user": "postgres",
        "password": "password",
        "ssl": false
    }
}
```

## Storage Modes

### JSON Mode (Default)

Stores entire payload in JSONB column:

```json
{
    "storage_mode": "json"
}
```

### Relational Mode

Maps payload fields to table columns with schema validation:

```json
{
    "storage_mode": "relational",
    "schema": {
        "event_id": "VARCHAR(255)",
        "event_type": "VARCHAR(100)",
        "timestamp": "TIMESTAMP"
    }
}
```

### Hybrid Mode

Stores mapped fields in columns + full payload in JSONB:

```json
{
    "storage_mode": "hybrid",
    "schema": {
        "event_id": "VARCHAR(255)",
        "event_type": "VARCHAR(100)"
    }
}
```

## Module Configuration Options

- `table`: Table name (required)
- `storage_mode`: "json", "relational", or "hybrid" (default: "json")
- `upsert`: Whether to use INSERT ... ON CONFLICT UPDATE (default: false)
- `upsert_key`: Column name for upsert key
- `include_headers`: Whether to include HTTP headers (default: false)
- `schema`: Column definitions for relational/hybrid modes

## Features

- Multiple storage modes
- Automatic table creation
- Upsert support
- Connection pooling
- Transaction support

