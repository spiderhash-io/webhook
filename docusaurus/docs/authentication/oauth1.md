# OAuth 1.0 Authentication

Authenticate webhooks using OAuth 1.0 signatures (RFC 5849), commonly used by legacy APIs like Twitter.

## Configuration

```json
{
    "oauth1_webhook": {
        "data_type": "json",
        "module": "log",
        "oauth1": {
            "consumer_key": "{$OAUTH1_CONSUMER_KEY}",
            "consumer_secret": "{$OAUTH1_CONSUMER_SECRET}",
            "token_secret": "{$OAUTH1_TOKEN_SECRET:}",
            "signature_method": "HMAC-SHA1",
            "verify_timestamp": true,
            "timestamp_window": 300
        }
    }
}
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `consumer_key` | string | Required | OAuth 1.0 consumer key |
| `consumer_secret` | string | Required | OAuth 1.0 consumer secret |
| `token_secret` | string | `""` | Token secret (for three-legged OAuth) |
| `signature_method` | string | `"HMAC-SHA1"` | Signature method |
| `verify_timestamp` | boolean | `true` | Whether to validate timestamp |
| `timestamp_window` | integer | `300` | Maximum timestamp difference in seconds |

## Supported Signature Methods

| Method | Description |
|--------|-------------|
| `HMAC-SHA1` | HMAC with SHA-1 (default, most common) |
| `PLAINTEXT` | Plain text signature (only use over HTTPS) |

:::warning RSA-SHA1
RSA-SHA1 is not supported for validation as it requires the private key.
:::

## Usage

Send requests with OAuth Authorization header:

```bash
curl -X POST http://localhost:8000/webhook/oauth1_webhook \
  -H "Authorization: OAuth oauth_consumer_key=\"...\", oauth_signature=\"...\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"...\", oauth_nonce=\"...\", oauth_version=\"1.0\"" \
  -H "Content-Type: application/json" \
  -d '{"event": "test"}'
```

## Required OAuth Parameters

The following parameters must be present in the Authorization header:

- `oauth_consumer_key` - Consumer key
- `oauth_signature` - Request signature
- `oauth_signature_method` - Signature method used

Optional but recommended:
- `oauth_timestamp` - Unix timestamp (required if `verify_timestamp` is enabled)
- `oauth_nonce` - Unique request identifier
- `oauth_version` - OAuth version (should be "1.0")

## Security Features

### Nonce Replay Protection

The system tracks used nonces to prevent replay attacks:

- Nonces are stored with their expiration time
- Reusing a nonce within the timestamp window triggers rejection
- Automatic cleanup of expired nonces

```
OAuth 1.0 nonce has already been used (replay attack detected)
```

### Timestamp Validation

When `verify_timestamp` is enabled:

- Request timestamp must be within `timestamp_window` seconds of server time
- Prevents old requests from being replayed
- Default window is 300 seconds (5 minutes)

### Constant-Time Comparison

Signature comparison uses `hmac.compare_digest` to prevent timing attacks.

## Signature Computation

### HMAC-SHA1

1. Build signature base string from HTTP method, URL, and sorted parameters
2. Create signing key: `{consumer_secret}&{token_secret}`
3. Compute HMAC-SHA1 of base string with signing key
4. Base64 encode the result

### PLAINTEXT

For PLAINTEXT signature method, the signature is simply:
```
{percent_encoded_consumer_secret}&{percent_encoded_token_secret}
```

:::warning Security
Only use PLAINTEXT over HTTPS, as the signature reveals the secrets.
:::

## Example: Twitter-style Webhook

```json
{
    "twitter_webhook": {
        "data_type": "json",
        "module": "rabbitmq",
        "connection": "rabbitmq_prod",
        "module-config": {
            "queue_name": "twitter_events"
        },
        "oauth1": {
            "consumer_key": "{$TWITTER_CONSUMER_KEY}",
            "consumer_secret": "{$TWITTER_CONSUMER_SECRET}",
            "signature_method": "HMAC-SHA1",
            "verify_timestamp": true,
            "timestamp_window": 300
        }
    }
}
```
