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

- `consumer_key`: OAuth 1.0 consumer key (required)
- `consumer_secret`: OAuth 1.0 consumer secret (required)
- `token_secret`: Optional token secret (for three-legged OAuth)
- `signature_method`: Signature method - `HMAC-SHA1` (default) or `PLAINTEXT`
- `verify_timestamp`: Whether to validate timestamp (default: `true`)
- `timestamp_window`: Maximum allowed timestamp difference in seconds (default: `300`)

## Usage

Send requests with OAuth Authorization header:

```bash
curl -X POST http://localhost:8000/webhook/oauth1_webhook \
  -H "Authorization: OAuth oauth_consumer_key=\"...\", oauth_signature=\"...\", oauth_timestamp=\"...\", oauth_nonce=\"...\", oauth_version=\"1.0\"" \
  -H "Content-Type: application/json" \
  -d '{"event": "test"}'
```

## Features

- Signature validation using HMAC-SHA1 or PLAINTEXT
- Timestamp validation (prevents replay attacks)
- Consumer key validation
- Constant-time signature comparison
- Nonce support

