# Log Module

The Log Module outputs webhook payloads to stdout. This is useful for debugging and development.

## Configuration

```json
{
    "log_webhook": {
        "data_type": "json",
        "module": "log",
        "module-config": {
            "pretty_print": true,
            "redact_sensitive": true
        },
        "authorization": "Bearer token"
    }
}
```

## Module Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `pretty_print` | boolean | `false` | Enable JSON formatted output with indentation |
| `redact_sensitive` | boolean | `true` | Redact sensitive data like passwords, tokens, API keys |

## Security Features

### Sensitive Data Redaction

When `redact_sensitive` is `true` (default), the following keys are automatically redacted:

- `password`, `passwd`, `pwd`, `secret`
- `token`, `api_key`, `apikey`
- `access_token`, `refresh_token`
- `authorization`, `auth`, `credential`
- `private_key`, `session`, `cookie`
- `database_url`, `connection_string`
- And more...

Example output with redaction:
```json
{
  "event": "user.created",
  "api_key": "[REDACTED]",
  "data": {
    "user_id": 123,
    "password": "[REDACTED]"
  }
}
```

### Output Limits

- **Maximum output length**: 10,000 characters (prevents DoS)
- **Maximum recursion depth**: 10 levels
- **Log injection prevention**: Newlines and control characters are sanitized

## Output Modes

### Standard Mode (default)

```
config: {'data_type': 'json', 'module': 'log', ...}
headers: {'content-type': 'application/json', 'authorization': '[REDACTED]'}
body: {'event': 'test', 'data': 'example'}
```

### Pretty Print Mode

```
================================================================================
WEBHOOK RECEIVED
================================================================================

Headers:
{
  "content-type": "application/json",
  "authorization": "[REDACTED]"
}

Payload:
{
  "event": "test",
  "data": "example"
}
================================================================================
```

## Features

- Simple stdout output
- No external dependencies
- Sensitive data redaction (enabled by default)
- Pretty print mode for debugging
- Log injection prevention
- Output size limits
- Circular reference handling

## Example: Development Debugging

```json
{
    "debug_webhook": {
        "data_type": "json",
        "module": "log",
        "module-config": {
            "pretty_print": true,
            "redact_sensitive": false
        }
    }
}
```

:::warning Security
Only set `redact_sensitive: false` in development environments. In production, always use the default `true` to prevent sensitive data exposure in logs.
:::
