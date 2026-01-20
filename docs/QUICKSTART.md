# Quick Start Guide

Get up and running with Core Webhook Module in 5 minutes!

## Prerequisites

- Python 3.9 or higher (or Docker)
- Basic understanding of webhooks and JSON

## Option 1: Docker (Fastest)

### 1. Pull the Docker Image

```bash
docker pull spiderhash/webhook:latest
```

### 2. Create Configuration Files

Create a directory for your configs:

```bash
mkdir -p config/development
```

Create `config/development/webhooks.json`:

```json
{
  "my_first_webhook": {
    "data_type": "json",
    "module": "log",
    "authorization": "Bearer my_secret_token_123"
  }
}
```

Create `config/development/connections.json`:

```json
{}
```

### 3. Run the Container

```bash
docker run --rm \
  -p 8000:8000 \
  -v "$(pwd)/config/development:/app/config/development:ro" \
  spiderhash/webhook:latest
```

### 4. Test Your Webhook

Open a new terminal and send a test request:

```bash
curl -X POST http://localhost:8000/webhook/my_first_webhook \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer my_secret_token_123" \
  -d '{"message": "Hello from my first webhook!"}'
```

You should see the payload logged in the Docker container output!

---

## Option 2: Local Development (Python venv)

### 1. Clone the Repository

```bash
git clone https://github.com/spiderhash-io/webhook.git
cd webhook
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Create Configuration Files

Copy example configurations:

```bash
cp config/examples/webhooks.example.json config/development/webhooks.json
cp config/examples/connections.example.json config/development/connections.json
```

Edit `config/development/webhooks.json` to keep only one simple webhook:

```json
{
  "test_webhook": {
    "data_type": "json",
    "module": "log",
    "authorization": "Bearer test_token_123"
  }
}
```

### 5. Run the Server

```bash
uvicorn src.main:app --reload
```

### 6. Test Your Webhook

```bash
curl -X POST http://localhost:8000/webhook/test_webhook \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer test_token_123" \
  -d '{"event": "test", "data": {"user": "john", "action": "signup"}}'
```

---

## Explore the API Documentation

Open your browser and visit:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

The API documentation is automatically generated from your `webhooks.json` configuration!

---

## Next Steps

### 1. Add More Output Modules

Try saving webhook data to disk:

```json
{
  "save_webhook": {
    "data_type": "json",
    "module": "save_to_disk",
    "module-config": {
      "path": "webhooks/incoming"
    },
    "authorization": "Bearer save_token_456"
  }
}
```

Test it:

```bash
curl -X POST http://localhost:8000/webhook/save_webhook \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer save_token_456" \
  -d '{"timestamp": "2025-01-20T18:00:00Z", "event": "user_created"}'
```

Check the `webhooks/incoming/` directory for your saved files!

### 2. Add Authentication Methods

Try HMAC signature validation:

```json
{
  "github_webhook": {
    "data_type": "json",
    "module": "log",
    "authorization": "Bearer token",
    "hmac": {
      "secret": "your_github_webhook_secret",
      "header": "X-Hub-Signature-256",
      "algorithm": "sha256"
    }
  }
}
```

### 3. Chain Multiple Destinations

Send webhook data to multiple places:

```json
{
  "chained_webhook": {
    "data_type": "json",
    "chain": [
      {
        "module": "save_to_disk",
        "module-config": {"path": "webhooks/archive"}
      },
      {
        "module": "log"
      }
    ],
    "chain-config": {
      "execution": "sequential",
      "continue_on_error": true
    },
    "authorization": "Bearer chain_token_789"
  }
}
```

### 4. Add External Services

#### RabbitMQ Example

Add to `connections.json`:

```json
{
  "rabbitmq_local": {
    "type": "rabbitmq",
    "host": "localhost",
    "port": 5672,
    "user": "guest",
    "pass": "guest"
  }
}
```

Add to `webhooks.json`:

```json
{
  "rabbitmq_webhook": {
    "data_type": "json",
    "module": "rabbitmq",
    "connection": "rabbitmq_local",
    "module-config": {
      "queue_name": "webhook_events"
    },
    "authorization": "Bearer rabbitmq_token"
  }
}
```

#### Redis Example

Add to `connections.json`:

```json
{
  "redis_local": {
    "type": "redis-rq",
    "host": "localhost",
    "port": 6379,
    "db": 0
  }
}
```

Add to `webhooks.json`:

```json
{
  "redis_webhook": {
    "data_type": "json",
    "module": "redis_rq",
    "connection": "redis_local",
    "module-config": {
      "queue_name": "webhook_tasks",
      "function": "process_webhook"
    },
    "authorization": "Bearer redis_token"
  }
}
```

---

## Common Use Cases

### Receiving GitHub Webhooks

```json
{
  "github_push": {
    "data_type": "json",
    "module": "save_to_disk",
    "module-config": {
      "path": "github/push_events"
    },
    "hmac": {
      "secret": "your_github_webhook_secret",
      "header": "X-Hub-Signature-256",
      "algorithm": "sha256"
    }
  }
}
```

### Receiving Stripe Webhooks

```json
{
  "stripe_events": {
    "data_type": "json",
    "module": "postgresql",
    "connection": "postgres_local",
    "module-config": {
      "table": "stripe_events",
      "storage_mode": "json"
    },
    "hmac": {
      "secret": "your_stripe_webhook_secret",
      "header": "Stripe-Signature",
      "algorithm": "sha256"
    }
  }
}
```

---

## Troubleshooting

### Issue: "Authorization header missing or invalid"

**Solution**: Make sure you're sending the correct `Authorization` header:

```bash
curl -H "Authorization: Bearer your_token_here" ...
```

### Issue: "Webhook ID not found"

**Solution**: Check that your webhook ID in the URL matches the key in `webhooks.json`:

- URL: `http://localhost:8000/webhook/my_webhook_id`
- Config: `{"my_webhook_id": {...}}`

### Issue: Module connection failed

**Solution**: 
1. Check that the service (RabbitMQ, Redis, etc.) is running
2. Verify connection details in `connections.json`
3. Check Docker network settings if using Docker

### Issue: Configuration changes not taking effect

**Solution**: 
- **Without file watching**: Restart the server
- **With file watching**: Wait 3 seconds (default debounce time) or manually reload:

```bash
curl -X POST http://localhost:8000/admin/reload-config \
  -H "Authorization: Bearer admin_token"
```

---

## Learn More

- **Full Documentation**: [README.md](../README.md)
- **Architecture Guide**: [ARCHITECTURE.md](ARCHITECTURE.md)
- **Module Development**: [docs/ARCHITECTURE.md](ARCHITECTURE.md#adding-a-new-module)
- **Configuration Examples**: [config/examples/](../config/examples/)
- **Contributing**: [CONTRIBUTING.md](../CONTRIBUTING.md)

---

## Need Help?

- **Issues**: [GitHub Issues](https://github.com/spiderhash-io/webhook/issues)
- **Discussions**: [GitHub Discussions](https://github.com/spiderhash-io/webhook/discussions)
- **Documentation**: [README.md](../README.md)

---

**Congratulations!** You've completed the quick start guide. You now have a working webhook receiver that you can customize for your specific needs.

Happy webhooking! 🎉
