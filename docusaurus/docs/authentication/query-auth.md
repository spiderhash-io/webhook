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

- `parameter_name`: Query parameter name (default: `"api_key"`)
- `api_key`: Expected API key value (required)
- `case_sensitive`: Whether key comparison is case-sensitive (default: `false`)

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

## Features

- Constant-time key comparison (timing attack resistant)
- Case-insensitive by default (configurable)
- Validates empty keys and missing parameters
- Handles special characters and Unicode

