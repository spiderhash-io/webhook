# Retry Mechanism Integration Test

This document describes how to test the retry mechanism with a Redis failure scenario.

## Prerequisites

1. Docker and Docker Compose installed
2. Redis running in Docker (via docker-compose)
3. Webhook service running on port 8000
4. Python dependencies installed

## Setup

1. **Start the webhook service:**
   ```bash
   # In one terminal
   source venv/bin/activate
   uvicorn src.main:app --reload --port 8000
   ```

2. **Ensure Redis is running:**
   ```bash
   docker-compose up -d redis
   # Or if using docker directly:
   docker run -d -p 6379:6379 --name redis-test redis:latest
   ```

3. **Verify Redis container name:**
   ```bash
   docker ps | grep redis
   ```
   Update `REDIS_CONTAINER_NAME` in `test_retry_redis.py` if your container name differs.

## Running the Test

```bash
# Make sure you're in the project root
source venv/bin/activate
python test_retry_redis.py
```

## What the Test Does

1. **Phase 1**: Sends 5 requests while Redis is running (should succeed with 200 OK)
2. **Phase 2**: Stops Redis and sends 15 more requests (should return 202 Accepted - retries in progress)
3. **Phase 3**: Restarts Redis and waits for retries to complete
4. **Phase 4**: Verifies all requests were handled

## Expected Behavior

- **Requests 1-5**: Should return `200 OK` (Redis is running)
- **Requests 6-20**: Should return `202 Accepted` (Redis stopped, retries happening)
- **After Redis restart**: Retries should succeed in the background
- **Final verification**: All requests should eventually be processed

## Configuration

The test uses the `redis_test` webhook configured in `webhooks.json`:

```json
{
  "redis_test": {
    "data_type": "json",
    "module": "redis_publish",
    "redis": {
      "host": "localhost",
      "port": 6379,
      "channel": "webhook_events"
    },
    "retry": {
      "enabled": true,
      "max_attempts": 5,
      "initial_delay": 1.0,
      "max_delay": 10.0,
      "backoff_multiplier": 2.0
    }
  }
}
```

## Monitoring Retries

To monitor retries in real-time, watch the webhook service logs:

```bash
# In the terminal running uvicorn, you should see:
# - "Module execution failed (attempt 1/5): ConnectionError..."
# - "Retrying in 1.00 seconds..."
# - "Module execution succeeded after 2 attempts" (after Redis restarts)
```

## Troubleshooting

1. **Redis container not found:**
   - Check container name: `docker ps | grep redis`
   - Update `REDIS_CONTAINER_NAME` in test script

2. **Webhook service not responding:**
   - Ensure service is running on port 8000
   - Check logs for errors

3. **All requests fail:**
   - Verify Redis configuration in `webhooks.json`
   - Check Redis is accessible on localhost:6379
   - Ensure retry is enabled in configuration

4. **Retries not happening:**
   - Check webhook configuration has `"retry": {"enabled": true}`
   - Verify service logs show retry attempts
   - Check that errors are retryable (ConnectionError, TimeoutError, etc.)

## Success Criteria

✅ Test passes if:
- All requests return either 200 OK or 202 Accepted
- No requests return 500 or other error codes
- Service logs show retry attempts when Redis is down
- Service logs show successful retries after Redis restarts

