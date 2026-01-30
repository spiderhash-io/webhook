# Query Parameter Authentication

Authenticate webhooks using API keys passed as query parameters (e.g., `?api_key=xxx`).

## Configuration

```json
{
    "query_auth_webhook": {
        "data_type": "json",
        "module": "log",
        "query_auth": {
            "parameter_name": "api_key",
            "api_key": "{$QUERY_AUTH_KEY:secret_api_key_123}",
            "case_sensitive": false
        }
    }
}
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `parameter_name` | string | `"api_key"` | Query parameter name |
| `api_key` | string | Required | Expected API key value |
| `case_sensitive` | boolean | `false` | Whether key comparison is case-sensitive |

## Usage

Send requests with API key in query string:

```bash
curl -X POST "http://localhost:8000/webhook/query_auth_webhook?api_key=secret_api_key_123" \
  -H "Content-Type: application/json" \
  -d '{"event": "test"}'
```

## Common Parameter Names

- `api_key`
- `token`
- `key`
- `apikey`
- `access_token`
- `auth_token`

## Security Features

- **Constant-time comparison** - Timing attack resistant using `hmac.compare_digest`
- **Parameter name validation** - Only alphanumeric characters and underscores allowed
- **Value sanitization** - Control characters (`\n`, `\r`, `\t`, `\0`) are removed
- **Length limits** - Maximum parameter value length enforced
- **Type validation** - API key must be a string

:::info Value Sanitization
Query parameter values are sanitized before comparison:
- Control characters are removed
- Null bytes are stripped
- Non-printable characters are filtered

This means special characters and Unicode in the provided API key may be modified during validation. Use alphanumeric characters for reliable key matching.
:::

## Error Messages

| Condition | Error Message |
|-----------|---------------|
| Missing parameter | `Missing required query parameter: {name}` |
| Invalid value | `Invalid API key in query parameter: {name}` |
| Invalid config | `Query auth API key not configured` |
| Too long / invalid chars | `Invalid query parameter value for: {name}` |
