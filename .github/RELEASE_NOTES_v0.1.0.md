# Release v0.1.0 - Initial Public Release

We're excited to announce the first public release of Core Webhook Module! This release marks the open-sourcing of our production-ready webhook receiver and processor.

## 🎉 Highlights

- **FastAPI-based webhook receiver** with configuration-driven architecture
- **11 authentication methods** including JWT, HMAC, OAuth 1.0/2.0, reCAPTCHA, and more
- **17 output modules** supporting RabbitMQ, Kafka, Redis, PostgreSQL, MySQL, S3, SQS, Pub/Sub, MQTT, and more
- **Webhook chaining** for sequential/parallel execution across multiple destinations
- **Cloud-to-local relay** (Webhook Connect) for receiving webhooks behind firewalls
- **Live configuration reload** without service restart
- **2,493+ passing tests** with 90%+ code coverage

## 🚀 Key Features

### Core Functionality
- Configuration-driven architecture via JSON files
- Live configuration reload without restart
- Connection pool management with automatic lifecycle
- Distributed analytics with ClickHouse
- Plugin architecture for extensible modules
- Webhook chaining (sequential and parallel execution)

### Authentication Methods (11 total)
- Bearer Token
- HTTP Basic Auth
- JWT with claims verification
- HMAC (SHA256/SHA1/SHA512)
- IP Whitelisting
- Header-based (X-API-Key)
- Query Parameter
- HTTP Digest
- OAuth 1.0
- OAuth 2.0
- Google reCAPTCHA (v2 & v3)

### Output Modules (17 total)
- Log (stdout)
- Save to disk
- RabbitMQ
- Redis RQ
- Redis Pub/Sub
- HTTP forwarding
- Apache Kafka
- MQTT (with Shelly/Tasmota support)
- WebSocket
- ClickHouse
- PostgreSQL (JSON/relational/hybrid modes)
- MySQL/MariaDB
- AWS S3
- AWS SQS
- GCP Pub/Sub
- ActiveMQ
- ZeroMQ

### Security Features
- Multi-layer validation
- Constant-time HMAC comparison
- Rate limiting with sliding window
- Automatic credential redaction
- Payload validation
- JSON schema validation
- Input sanitization

### Webhook Connect (Cloud-to-Local Relay)
Similar to ngrok for webhooks:
- Cloud webhook receiver with public endpoints
- WebSocket and SSE streaming
- Channel-based isolation with HMAC auth
- Message acknowledgments and retries
- Dead-letter queue
- Multi-target forwarding

## 📦 Installation

### Docker (Recommended)
```bash
docker pull spiderhash/webhook:0.1.0
docker run -p 8000:8000 -v $(pwd)/config:/app/config spiderhash/webhook:0.1.0
```

### From Source
```bash
git clone https://github.com/spiderhash-io/webhook.git
cd webhook
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python src/main.py
```

## 📚 Documentation

- [README.md](https://github.com/spiderhash-io/webhook/blob/main/README.md) - Overview and quick start
- [ARCHITECTURE.md](https://github.com/spiderhash-io/webhook/blob/main/ARCHITECTURE.md) - Architecture details
- [CONTRIBUTING.md](https://github.com/spiderhash-io/webhook/blob/main/CONTRIBUTING.md) - Contribution guidelines
- [SECURITY.md](https://github.com/spiderhash-io/webhook/blob/main/SECURITY.md) - Security policy
- [docs/QUICKSTART.md](https://github.com/spiderhash-io/webhook/blob/main/docs/QUICKSTART.md) - 5-minute setup guide

## 🔧 Configuration Example

Create `config/webhooks.json`:
```json
{
  "github_webhook": {
    "data_type": "json",
    "module": "rabbitmq",
    "authorization": "Bearer {$GITHUB_WEBHOOK_TOKEN}",
    "hmac-verification": {
      "secret": "{$GITHUB_WEBHOOK_SECRET}",
      "header": "X-Hub-Signature-256",
      "algorithm": "sha256"
    },
    "module-config": {
      "connection": "rabbitmq_main",
      "exchange": "webhooks",
      "routing_key": "github.events"
    }
  }
}
```

## 🧪 Testing

This release includes:
- 2,493+ passing unit and integration tests
- 90%+ code coverage
- Security audit tests
- Performance tests
- Integration tests for all modules

Run tests:
```bash
make test           # Unit tests
make test-all       # All tests
make test-cov       # With coverage
```

## 🔒 Security

This project takes security seriously:
- 11 authentication methods
- Multi-layer validation
- Rate limiting
- Credential redaction
- Automated security scanning (Bandit, Safety, CodeQL, Trivy)

Report security issues: https://github.com/spiderhash-io/webhook/security/policy

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](https://github.com/spiderhash-io/webhook/blob/main/CONTRIBUTING.md) for guidelines.

## 📄 License

MIT License - see [LICENSE](https://github.com/spiderhash-io/webhook/blob/main/LICENSE)

## 🙏 Acknowledgments

Thank you to all contributors and early users who helped test and improve this project!

## 📌 What's Next?

Future plans include:
- Prometheus/Grafana metrics integration
- Distributed tracing with OpenTelemetry
- Payload transformation pipelines
- Cloudflare Turnstile validation
- Circuit breakers for failing modules

See [CHANGELOG.md](https://github.com/spiderhash-io/webhook/blob/main/CHANGELOG.md) for complete details.

---

**Full Changelog**: https://github.com/spiderhash-io/webhook/commits/v0.1.0
