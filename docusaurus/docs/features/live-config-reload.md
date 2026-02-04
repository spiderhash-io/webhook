# Live Config Reload

Hot-reload webhook and connection configurations without restarting the application.

## Setup

### 1. Configure Admin Authentication (Required)

:::warning Authentication Required
Admin endpoints require the `CONFIG_RELOAD_ADMIN_TOKEN` environment variable to be set.
The admin API is **disabled** (returns `403 Forbidden`) if this token is not configured.
:::

Generate and set a secure admin token:

```bash
# Using OpenSSL (Linux/macOS)
export CONFIG_RELOAD_ADMIN_TOKEN=$(openssl rand -base64 32)

# Using Python
export CONFIG_RELOAD_ADMIN_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
```

:::tip Token Security
- Store the token securely (use secrets management in production)
- Never commit tokens to version control
- Rotate tokens periodically
- Use different tokens for different environments
:::

### 2. Enable File Watching (Optional)

```bash
export CONFIG_FILE_WATCHING_ENABLED=true
export CONFIG_RELOAD_DEBOUNCE_SECONDS=3.0
```

## Manual Reload via API

### Reload Webhook Configurations

```bash
curl -X POST http://localhost:8000/admin/reload-config \
  -H "Authorization: Bearer $CONFIG_RELOAD_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reload_webhooks": true}'
```

### Reload Connection Configurations

```bash
curl -X POST http://localhost:8000/admin/reload-config \
  -H "Authorization: Bearer $CONFIG_RELOAD_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reload_connections": true}'
```

### Check Configuration Status

```bash
curl -X GET http://localhost:8000/admin/config-status \
  -H "Authorization: Bearer $CONFIG_RELOAD_ADMIN_TOKEN"
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

- `CONFIG_RELOAD_ADMIN_TOKEN`: **Required** - Admin token for API endpoints. Admin API is disabled if unset.
- `CONFIG_FILE_WATCHING_ENABLED`: Enable automatic file watching (default: `false`)
- `CONFIG_RELOAD_DEBOUNCE_SECONDS`: Debounce time in seconds (default: `3.0`)

## Security

- **Admin endpoints require authentication** via `CONFIG_RELOAD_ADMIN_TOKEN`
- **Admin API disabled by default** - returns `403 Forbidden` if token not set
- **Constant-time token comparison** prevents timing attacks
- **Header injection protection** blocks malicious headers (newlines, null bytes)
- Configuration validation prevents invalid updates
- Error sanitization prevents information disclosure
- Thread-safe operations prevent race conditions

## Migration from Previous Versions

:::danger Breaking Change
**Version 2.x** introduces a breaking change: Admin endpoints now **require** `CONFIG_RELOAD_ADMIN_TOKEN`
to be set. Previously, these endpoints were accessible without authentication when the environment
variable was unset.
:::

### What Changed

- Admin endpoints (`/admin/reload-config`, `/admin/config-status`) return `403 Forbidden` when `CONFIG_RELOAD_ADMIN_TOKEN` is not set
- Whitespace-only tokens are now treated as unconfigured (return `403` instead of `401`)
- Token validation uses constant-time comparison to prevent timing attacks

### Action Required

If you're upgrading from a previous version:

1. **Set the admin token** before deploying:
   ```bash
   export CONFIG_RELOAD_ADMIN_TOKEN="your-secure-random-token"
   ```

2. **Update your deployment scripts** to include the environment variable:
   ```bash
   # In your .env file
   CONFIG_RELOAD_ADMIN_TOKEN=your-secure-token-here
   ```

3. **Update API calls** to use the correct token:
   ```bash
   curl -X POST http://localhost:8000/admin/reload-config \
     -H "Authorization: Bearer $CONFIG_RELOAD_ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"reload_webhooks": true}'
   ```

### Error Responses

| Scenario | Status Code | Response |
|----------|-------------|----------|
| Token not configured | `403` | `{"detail": "Admin API disabled. Set CONFIG_RELOAD_ADMIN_TOKEN environment variable."}` |
| Missing Authorization header | `401` | `{"detail": "Authentication required"}` |
| Invalid token | `401` | `{"detail": "Invalid authentication token"}` |
| Malformed header | `401` | `{"detail": "Invalid authentication header"}` |

