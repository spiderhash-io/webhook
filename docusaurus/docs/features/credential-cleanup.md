# Credential Cleanup

Automatically clean credentials from webhook payloads and headers before logging or storing to prevent credential exposure.

## Configuration

```json
{
    "secure_webhook": {
        "data_type": "json",
        "module": "postgresql",
        "credential_cleanup": {
            "enabled": true,
            "mode": "mask",
            "fields": ["password", "api_key", "custom_secret"]
        }
    }
}
```

## Configuration Options

- `enabled`: Enable credential cleanup (default: `true` - opt-out behavior)
- `mode`: Cleanup mode - `"mask"` replaces with `***REDACTED***` or `"remove"` deletes the field (default: `"mask"`)
- `fields`: Optional list of additional custom field names to treat as credentials (default fields are always included)

## Default Credential Fields

The following field names are automatically detected as credentials (case-insensitive):

- `password`, `passwd`, `pwd`
- `secret`, `api_secret`, `client_secret`
- `token`, `api_key`, `apikey`, `access_token`, `refresh_token`
- `authorization`, `auth`, `credential`, `credentials`
- `private_key`, `privatekey`
- `bearer`, `x-api-key`, `x-auth-token`, `x-access-token`
- `session_id`, `sessionid`, `session_token`
- `csrf_token`, `csrf`
- `oauth_token`, `oauth_secret`, `consumer_secret`, `token_secret`

## Usage

### Mask Mode (Default)

Replaces credential values with `***REDACTED***`:

**Input:**
```json
{
    "username": "user123",
    "password": "secret123",
    "api_key": "key456"
}
```

**Output:**
```json
{
    "username": "user123",
    "password": "***REDACTED***",
    "api_key": "***REDACTED***"
}
```

### Remove Mode

Deletes credential fields entirely:

**Input:**
```json
{
    "username": "user123",
    "password": "secret123",
    "api_key": "key456"
}
```

**Output:**
```json
{
    "username": "user123"
}
```

## Features

- Automatic credential detection
- Custom field support
- Nested JSON structure support
- Header cleaning
- Always enabled for ClickHouse analytics logs
- Pattern-based detection

