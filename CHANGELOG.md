# Changelog

All notable changes to Core Webhook Module will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Prometheus/Grafana metrics integration
- Distributed tracing with OpenTelemetry
- Payload transformation (pre-processing step)
- Cloudflare Turnstile validation
- Circuit breakers for failing modules

## [0.1.0] - 2025-01-20

### Added - Initial Release

#### Core Features
- FastAPI-based webhook receiver and processor
- Configuration-driven architecture via JSON files
- Live configuration reload without restart
- Connection pool management with automatic lifecycle
- Distributed analytics with ClickHouse
- Plugin architecture for extensible modules
- Webhook chaining (sequential and parallel execution)

#### Authentication Methods (11 total)
- Bearer Token authorization
- HTTP Basic Authentication
- JWT token validation with claims verification
- HMAC signature validation (SHA256/SHA1/SHA512)
- IP whitelisting
- Header-based authentication (X-API-Key)
- Query parameter authentication
- HTTP Digest Authentication
- OAuth 1.0 authentication
- OAuth 2.0 authentication (introspection & JWT)
- Google reCAPTCHA validation (v2 & v3)

#### Output Modules (17 total)
- Log module (stdout)
- Save to disk module
- RabbitMQ message queue
- Redis RQ task queue
- Redis Pub/Sub
- HTTP webhook forwarding
- Apache Kafka
- MQTT publishing (with Shelly/Tasmota support)
- WebSocket forwarding
- ClickHouse analytics
- PostgreSQL storage (JSON/relational/hybrid modes)
- MySQL/MariaDB storage
- AWS S3 object storage
- AWS SQS queue
- GCP Pub/Sub
- ActiveMQ
- ZeroMQ

#### Security Features
- Multi-layer validation combining multiple auth methods
- Constant-time comparison for HMAC/token validation
- Rate limiting with sliding window algorithm
- Credential cleanup (automatic redaction in logs/storage)
- Payload validation (size, depth, string length limits)
- JSON schema validation
- Input sanitization
- CORS support

#### Observability
- Structured logging with correlation IDs
- In-memory metrics tracking
- ClickHouse analytics logging
- Statistics API (`/stats`)
- Task manager with backpressure handling

#### Webhook Connect (Cloud-to-Local Relay)
- Cloud webhook receiver with public endpoints
- WebSocket and SSE streaming protocols
- Channel-based isolation with HMAC authentication
- Message acknowledgments and retries
- Dead-letter queue for failed deliveries
- Multi-target forwarding support

#### Performance Improvements
- Parallel execution timeout protection (configurable, default 30s)
- Automatic task cancellation on failure
- Background credential cleanup (no request latency impact)
- Module config pre-building optimization
- Fail-fast on circular references

#### Developer Experience
- Dynamic OpenAPI documentation generation
- Swagger UI and ReDoc interfaces
- Environment variable substitution in configs
- Docker support with multi-arch images
- Comprehensive test suite (2,493+ passing tests, 90%+ coverage)
- Development and production deployment examples

### Documentation
- Architecture documentation
- Development guide
- Performance testing guide
- Live config reload documentation
- Webhook chaining feature guide
- Security scanning guide
- Module development guide
- Comprehensive README with examples

### Testing
- 2,493+ passing unit and integration tests
- 90%+ code coverage
- Security audit tests
- Performance tests
- Integration tests for all modules
- CI/CD with GitLab CI

### Infrastructure
- Docker images (single and multi-instance)
- Docker Compose configurations
- Kubernetes manifests (examples)
- GitHub Actions workflows
- Automated security scanning (Bandit, Safety, CodeQL, Trivy)

## Version History

### Versioning Strategy

This project uses [Semantic Versioning](https://semver.org/):

- **MAJOR** version for incompatible API changes
- **MINOR** version for backwards-compatible functionality additions
- **PATCH** version for backwards-compatible bug fixes

### Support Policy

- Latest major version: Full support with security updates and new features
- Previous major version: Security updates only for 6 months after new major release
- Older versions: No longer supported

### Migration Guides

For major version upgrades, see [MIGRATION.md](docs/MIGRATION.md) for detailed migration instructions.

## Links

- [GitHub Repository](https://github.com/spiderhash-io/webhook)
- [Documentation](https://docs.spiderhash.io) (coming soon)
- [Docker Hub](https://hub.docker.com/r/spiderhash/webhook)
- [Issue Tracker](https://github.com/spiderhash-io/webhook/issues)
- [Discussions](https://github.com/spiderhash-io/webhook/discussions)
