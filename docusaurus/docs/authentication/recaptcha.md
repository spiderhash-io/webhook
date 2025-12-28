# Google reCAPTCHA Validation

Validate webhook requests using Google reCAPTCHA v2 or v3 to prevent bot submissions.

## reCAPTCHA v3 (Recommended)

```json
{
    "recaptcha_v3_webhook": {
        "data_type": "json",
        "module": "log",
        "recaptcha": {
            "secret_key": "your_recaptcha_v3_secret_key",
            "version": "v3",
            "token_source": "header",
            "token_field": "X-Recaptcha-Token",
            "min_score": 0.5
        }
    }
}
```

## reCAPTCHA v2

```json
{
    "recaptcha_v2_webhook": {
        "data_type": "json",
        "module": "log",
        "recaptcha": {
            "secret_key": "your_recaptcha_v2_secret_key",
            "version": "v2",
            "token_source": "body",
            "token_field": "g-recaptcha-response"
        }
    }
}
```

## Configuration Options

- `secret_key` (required): Your reCAPTCHA secret key from Google
- `version`: `"v2"` or `"v3"` (default: `"v3"`)
- `token_source`: `"header"` or `"body"` (default: `"header"`)
- `token_field`: Field name to look for token (default: `"X-Recaptcha-Token"`)
- `min_score`: Minimum score for v3 validation (default: `0.5`, range: 0.0-1.0)

## Usage

### Header-based tokens (v3 recommended)

Send token in `X-Recaptcha-Token` header:

```bash
curl -X POST http://localhost:8000/webhook/recaptcha_v3_webhook \
  -H "X-Recaptcha-Token: <recaptcha_token>" \
  -H "Content-Type: application/json" \
  -d '{"event": "test"}'
```

### Body-based tokens (v2)

Include token in JSON body:

```json
{
    "event": "test",
    "g-recaptcha-response": "<recaptcha_token>"
}
```

## Combined with other validators

```json
{
    "secure_webhook_with_recaptcha": {
        "data_type": "json",
        "module": "save_to_disk",
        "authorization": "Bearer token_123",
        "recaptcha": {
            "secret_key": "your_recaptcha_secret_key",
            "version": "v3",
            "token_source": "header",
            "min_score": 0.7
        }
    }
}
```

## Features

- reCAPTCHA v2 and v3 support
- Header or body token sources
- Score-based validation (v3)
- Bot protection
- Combined with other authentication methods

