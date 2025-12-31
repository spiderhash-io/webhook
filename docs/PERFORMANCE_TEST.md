# Performance Test Setup

This document describes how to run performance tests with multiple webhook instances, Redis, and ClickHouse.

## Architecture

The setup includes:
- **5 Webhook Instances** (ports 8000-8004) - Handle incoming webhook requests
- **Redis** (port 6380) - For rate limiting and caching
- **ClickHouse** (ports 8123, 9000) - For storing webhook events and analytics
- **Analytics Service** - Separate service that processes events from ClickHouse

## Prerequisites

- Docker and Docker Compose installed
- Python 3.9+ (for running the test script)
- httpx library: `pip install httpx`

## Quick Start

### Option 1: Using the automated script

```bash
./scripts/run_performance_test.sh
```

### Option 2: Manual steps

1. **Start all services:**
   ```bash
   docker compose -f docker/compose/docker-compose.yaml up -d
   ```

2. **Wait for services to be ready** (about 30 seconds):
   ```bash
   # Check ClickHouse
   docker compose -f docker/compose/docker-compose.yaml exec clickhouse wget --spider -q http://localhost:8123/ping
   
   # Check webhook instances
   curl http://localhost:8000/
   curl http://localhost:8001/
   ```

3. **Run the performance test:**
   ```bash
   python3 tests/unit/performance_test_multi_instance.py
   ```

## Test Configuration

The performance test is configured in `tests/unit/performance_test_multi_instance.py`:

- **Total Requests**: 10,000
- **Concurrency**: 200 requests per instance
- **Instances**: 5 webhook instances
- **Webhook ID**: `performance_test_webhook`

You can modify these values in the script to adjust the test load.

## Test Results

The test will output:

1. **Overall Statistics:**
   - Total requests and success/failure rates
   - Requests per second (RPS)
   - Average, median, min, max latencies
   - Percentiles (p50, p75, p90, p95, p99)

2. **Per-Instance Statistics:**
   - Success/failure rates per instance
   - Average latency per instance
   - RPS per instance

3. **Error Breakdown:**
   - Types of errors encountered
   - Error counts

## Verifying ClickHouse Data

After running the test, verify that data was written to ClickHouse:

```bash
# Check webhook_logs table
docker compose -f docker/compose/docker-compose.yaml exec clickhouse clickhouse-client --query 'SELECT count() FROM webhook_logs'

# View recent events
docker compose -f docker/compose/docker-compose.yaml exec clickhouse clickhouse-client --query 'SELECT webhook_id, count() as count FROM webhook_logs GROUP BY webhook_id'

# View sample events
docker compose -f docker/compose/docker-compose.yaml exec clickhouse clickhouse-client --query 'SELECT * FROM webhook_logs LIMIT 5'
```

## Monitoring Services

### View logs:

```bash
# All webhook instances
docker compose -f docker/compose/docker-compose.yaml logs -f webhook-1 webhook-2 webhook-3 webhook-4 webhook-5

# Analytics service
docker compose -f docker/compose/docker-compose.yaml logs -f analytics

# ClickHouse
docker compose -f docker/compose/docker-compose.yaml logs -f clickhouse

# Redis
docker compose -f docker/compose/docker-compose.yaml logs -f redis
```

### Check service status:

```bash
docker compose -f docker/compose/docker-compose.yaml ps
```

## Stopping Services

```bash
docker compose -f docker/compose/docker-compose.yaml down
```

To also remove volumes (including ClickHouse data):

```bash
docker compose -f docker/compose/docker-compose.yaml down -v
```

## Troubleshooting

### Services not starting

1. Check Docker is running: `docker info`
2. Check ports are available: `lsof -i :8000-8004`
3. View logs: `docker compose -f docker/compose/docker-compose.yaml logs`

### ClickHouse connection errors

1. Wait longer for ClickHouse to initialize (can take 30-60 seconds)
2. Check ClickHouse logs: `docker compose -f docker/compose/docker-compose.yaml logs clickhouse`
3. Verify ClickHouse is accessible: `curl http://localhost:8123/ping`

### Performance test failures

1. Ensure all webhook instances are responding:
   ```bash
   for port in 8000 8001 8002 8003 8004; do
     curl http://localhost:$port/
   done
   ```

2. Check webhook configuration:
   - Verify `webhooks.performance.json` exists
   - Verify `connections.docker.json` has correct service names

3. Increase timeout in test script if needed

## Customizing the Test

Edit `tests/unit/performance_test_multi_instance.py` to customize:

- `TOTAL_REQUESTS`: Total number of requests to send
- `CONCURRENCY`: Number of concurrent requests
- `WEBHOOK_INSTANCES`: List of instance URLs
- `TIMEOUT`: Request timeout in seconds

## Architecture Notes

- **Webhook instances** only send raw events to ClickHouse (no aggregation)
- **Analytics service** runs separately and processes events from ClickHouse
- All instances share the same Redis and ClickHouse services
- Each webhook instance runs independently on different ports

