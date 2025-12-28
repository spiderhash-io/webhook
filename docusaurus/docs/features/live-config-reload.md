# Live Config Reload

Hot-reload webhook and connection configurations without restarting the application.

## Enable File Watching

```bash
export CONFIG_FILE_WATCHING_ENABLED=true
export CONFIG_RELOAD_DEBOUNCE_SECONDS=3.0
```

## Manual Reload via API

### Reload Webhook Configurations

```bash
curl -X POST http://localhost:8000/admin/reload-config \
  -H "Authorization: Bearer admin_token"
```

### Reload Connection Configurations

```bash
curl -X POST http://localhost:8000/admin/reload-connections \
  -H "Authorization: Bearer admin_token"
```

## Features

- **Automatic file watching** with debouncing (default: 3 seconds)
- **Thread-safe** configuration updates
- **Connection pool lifecycle management** - old connections are properly closed
- **Validation before applying changes** - invalid configs are rejected
- **Rollback on errors** - previous configuration is restored if update fails
- **Zero-downtime updates** - webhooks continue processing during updates

## How It Works

1. **File Watching**: When `CONFIG_FILE_WATCHING_ENABLED=true`, the application watches `webhooks.json` and `connections.json` for changes
2. **Debouncing**: Changes are debounced (default: 3 seconds) to avoid reloading on every save
3. **Validation**: New configurations are validated before being applied
4. **Update**: If valid, configurations are updated atomically
5. **Connection Management**: Old connection pools are closed and new ones are created
6. **Rollback**: If an error occurs, the previous configuration is restored

## Environment Variables

- `CONFIG_FILE_WATCHING_ENABLED`: Enable automatic file watching (default: `false`)
- `CONFIG_RELOAD_DEBOUNCE_SECONDS`: Debounce time in seconds (default: `3.0`)

## Security

- Admin endpoints require authentication
- Configuration validation prevents invalid updates
- Error sanitization prevents information disclosure
- Thread-safe operations prevent race conditions

