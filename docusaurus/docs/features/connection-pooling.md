# Connection Pooling

Efficient connection management with automatic pool lifecycle, versioning, and graceful migration.

## Overview

The Core Webhook Module uses a centralized `ConnectionPoolRegistry` to manage connection pools for all database and message queue connections. This ensures efficient resource usage, prevents connection exhaustion, and enables zero-downtime configuration updates.

## Features

- **Pool Versioning**: Track multiple versions of pools for the same connection
- **Graceful Migration**: Old pools remain active during configuration transitions
- **Automatic Cleanup**: Deprecated pools are closed after a configurable timeout
- **Async-Safe**: Thread-safe operations for concurrent access
- **Config-Based Pooling**: Pools are automatically created based on connection configuration
- **Exhaustion Protection**: Built-in limits and timeouts prevent resource exhaustion

## How It Works

1. **Pool Creation**: When a connection is first used, a pool is created using the connection configuration
2. **Pool Reuse**: Subsequent requests reuse the existing pool if the configuration hasn't changed
3. **Config Changes**: When connection configuration changes, the old pool is deprecated and a new one is created
4. **Graceful Migration**: Old pools remain active for a migration timeout period (default: 5 minutes) to allow in-flight requests to complete
5. **Automatic Cleanup**: Deprecated pools are automatically closed after the migration timeout

## Supported Connection Types

Connection pooling is automatically enabled for:

- **PostgreSQL** - Uses `asyncpg` connection pools
- **MySQL/MariaDB** - Uses `aiomysql` connection pools
- **Redis** - Uses `aioredis` connection pools
- **RabbitMQ** - Custom connection pool implementation
- **Other modules** - Custom pool implementations as needed

## Configuration

Connection pools are configured through the connection configuration in `connections.json`:

```json
{
  "my_postgres_connection": {
    "type": "postgresql",
    "host": "localhost",
    "port": 5432,
    "database": "webhooks",
    "user": "webhook_user",
    "password": "secure_password",
    "pool_min_size": 2,
    "pool_max_size": 10
  }
}
```

### Pool Configuration Options

- `pool_min_size`: Minimum number of connections in the pool (default: varies by module)
- `pool_max_size`: Maximum number of connections in the pool (default: varies by module)
- `acquisition_timeout`: Maximum time to wait for a connection (default: varies by module)

## Migration Timeout

The migration timeout controls how long deprecated pools remain active after a configuration change:

- **Default**: 5 minutes (300 seconds)
- **Purpose**: Allows in-flight requests to complete before closing old pools
- **Configurable**: Can be adjusted via the `ConnectionPoolRegistry` constructor

## Security Features

- **Connection Limits**: Prevents resource exhaustion via configurable pool sizes
- **Timeout Protection**: Prevents indefinite waiting for connections
- **Error Sanitization**: Prevents information disclosure in error messages
- **Hash Collision Prevention**: Uses full SHA256 hashes for config comparison
- **Input Validation**: Validates all inputs to prevent injection attacks

## Monitoring

Connection pool status can be monitored via the admin API:

```bash
curl http://localhost:8000/admin/status \
  -H "Authorization: Bearer admin_token"
```

The status response includes:
- Active pools count
- Deprecated pools count
- Pool version information
- Active request counts

## Best Practices

1. **Set Appropriate Pool Sizes**: Balance between resource usage and performance
2. **Monitor Pool Usage**: Use the status endpoint to track pool utilization
3. **Configure Timeouts**: Set reasonable acquisition timeouts to prevent hanging requests
4. **Use Connection Pooling**: Always use connection pooling for database and queue connections
5. **Handle Pool Exhaustion**: Implement proper error handling for pool exhaustion scenarios

## Example

When a webhook configuration uses a PostgreSQL connection:

```json
{
  "webhooks": [
    {
      "path": "/webhook/example",
      "modules": [
        {
          "type": "postgresql",
          "connection": "my_postgres_connection"
        }
      ]
    }
  ]
}
```

The module will automatically:
1. Look up or create a connection pool for `my_postgres_connection`
2. Reuse the pool for subsequent webhook processing
3. Migrate to a new pool if the connection configuration changes
4. Clean up old pools after the migration timeout

