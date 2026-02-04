# Installation

## Local Development (venv)

1. Create a virtual environment (recommended):
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install development dependencies (includes production deps + testing tools):
   ```bash
   pip install -r requirements-dev.txt
   ```

3. Run the server:
   ```bash
   uvicorn src.main:app --reload
   ```

4. Run the tests:
   ```bash
   make test        # or: pytest -v
   ```

## Production Installation

For production deployments, install only production dependencies:
```bash
pip install -r requirements.txt
```

## Docker (Single Instance)

Use the optimized smaller image from Docker Hub to run a single FastAPI instance in Docker:

```bash
# Pull image from Docker Hub
docker pull spiderhash/webhook:latest

# Run container (mount configs from host)
docker run --rm \
  -p 8000:8000 \
  -v "$(pwd)/webhooks.json:/app/webhooks.json:ro" \
  -v "$(pwd)/connections.json:/app/connections.json:ro" \
  --env-file .env \
  spiderhash/webhook:latest
```

### Environment Variables

Create a `.env` file for your environment variables:

```bash
# Admin API Authentication (Required for /admin/* endpoints)
CONFIG_RELOAD_ADMIN_TOKEN=your-secure-token-here

# Live Config Reload (Optional)
CONFIG_FILE_WATCHING_ENABLED=true
CONFIG_RELOAD_DEBOUNCE_SECONDS=3.0

# Application Settings
DISABLE_OPENAPI_DOCS=false
ROOT_PATH=
```

:::tip Generating Secure Tokens
```bash
# Using OpenSSL (Linux/macOS)
openssl rand -base64 32

# Using Python
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```
:::

```

## Docker (Multi-Instance with Redis & ClickHouse)

For performance testing and a full deployment with multiple webhook instances:

```bash
# Start all services (5 webhook instances + ClickHouse + Redis + RabbitMQ + Analytics)
docker compose up -d

# Run performance tests
./src/tests/run_performance_test.sh
```

## Access the API

Once running, access:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`
- **OpenAPI JSON**: `http://localhost:8000/openapi.json`

