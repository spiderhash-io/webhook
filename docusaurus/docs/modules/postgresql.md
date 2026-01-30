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
            "upsert": false,
            "upsert_key": "event_id",
            "include_headers": true,
            "include_timestamp": true
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
        "ssl": false,
        "pool_min_size": 2,
        "pool_max_size": 10
    }
}
```

## Module Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `table` | string | `"webhook_events"` | Table name |
| `storage_mode` | string | `"json"` | Storage mode: `"json"`, `"relational"`, or `"hybrid"` |
| `upsert` | boolean | `false` | Enable INSERT ON CONFLICT UPDATE |
| `upsert_key` | string | `"id"` | Field name for upsert conflict key |
| `include_headers` | boolean | `true` | Store HTTP headers in JSONB column |
| `include_timestamp` | boolean | `true` | Add timestamp to records |
| `schema` | object | - | Schema definition for relational/hybrid modes |

## Storage Modes

### JSON Mode (Default)

Stores entire payload in JSONB column. Auto-creates table:

```sql
CREATE TABLE webhook_events (
    id UUID PRIMARY KEY,
    webhook_id TEXT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE,
    payload JSONB NOT NULL,
    headers JSONB,
    created_at TIMESTAMP WITH TIME ZONE
)
```

### Relational Mode

Maps payload fields to table columns. Requires `schema.fields` definition:

```json
{
    "storage_mode": "relational",
    "schema": {
        "fields": {
            "event_id": {
                "column": "event_id",
                "type": "string",
                "constraints": ["NOT NULL", "UNIQUE"]
            },
            "event_type": {
                "column": "event_type",
                "type": "string"
            },
            "amount": {
                "column": "amount",
                "type": "float"
            },
            "created_at": {
                "column": "created_at",
                "type": "datetime",
                "default": "CURRENT_TIMESTAMP"
            }
        },
        "indexes": {
            "idx_event_type": {
                "columns": ["event_type"]
            }
        }
    }
}
```

### Hybrid Mode

Stores mapped fields in columns + full payload in JSONB:

```json
{
    "storage_mode": "hybrid",
    "schema": {
        "fields": {
            "event_id": {
                "column": "event_id",
                "type": "string"
            }
        }
    }
}
```

## Supported Field Types

| Type | PostgreSQL Type |
|------|-----------------|
| `string`, `text` | TEXT |
| `integer`, `int` | BIGINT |
| `float`, `number` | DOUBLE PRECISION |
| `boolean`, `bool` | BOOLEAN |
| `datetime`, `timestamp` | TIMESTAMP WITH TIME ZONE |
| `date` | DATE |
| `time` | TIME |
| `json` | JSONB |

## Table Name Validation

Table names are validated for security:

- Maximum 63 characters
- Must start with letter or underscore
- Alphanumeric and underscore only
- Cannot be SQL keywords

## Features

- Three storage modes (JSON, relational, hybrid)
- Automatic table creation
- Upsert support (INSERT ON CONFLICT)
- Connection pooling
- SSL support
- Index creation
- SSRF protection for hostnames
