# Header-based Authentication

Authenticate webhooks using API keys passed in custom headers (e.g., `X-API-Key`, `X-Auth-Token`).

## Configuration

```json
{
    "header_auth_webhook": {
        "data_type": "json",
        "module": "log",
        "header_auth": {
            "header_name": "X-API-Key",
            "api_key": "{$HEADER_AUTH_KEY:secret_api_key_123}",
            "case_sensitive": false
        }
    }
}
```

## Configuration Options

- `header_name`: Header name to look for (default: `"X-API-Key"`)
- `api_key`: Expected API key value (required)
- `case_sensitive`: Whether key comparison is case-sensitive (default: `false`)

## Usage

Send requests with API key in custom header:

```bash
curl -X POST http://localhost:8000/webhook/header_auth_webhook \
  -H "X-API-Key: secret_api_key_123" \
  -H "Content-Type: application/json" \
  -d '{"event": "test"}'
```

## Common Header Names

- `X-API-Key`
- `X-Auth-Token`
- `X-Access-Token`
- `API-Key`

## Features

- Constant-time key comparison (timing attack resistant)
- Case-insensitive header name lookup
- Case-insensitive key comparison by default (configurable)
- Validates empty keys and missing headers

