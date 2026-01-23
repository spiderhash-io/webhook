# Webhook Connect Troubleshooting

This guide covers common issues and solutions when working with Webhook Connect.

## Connection Issues

### Connector Can't Connect to Cloud Receiver

**Symptoms:**
- Connector shows "Connection refused" or timeout errors
- Connector keeps reconnecting

**Possible Causes and Solutions:**

1. **Cloud receiver not running or unreachable:**
   ```bash
   # Check if cloud receiver is running
   curl http://cloud-receiver:8000/health

   # Expected response
   {"status": "healthy", "buffer": "connected", "channels": 3}
   ```

2. **Wrong URL in connector config:**
   ```json
   // Check the URL format
   {
       "cloud": {
           "url": "ws://cloud-receiver:8000/connect/stream",  // WebSocket
           // or
           "url": "http://cloud-receiver:8000/connect/stream"  // SSE
       }
   }
   ```

3. **Firewall blocking outbound connections:**
   ```bash
   # Test connectivity
   curl -v http://cloud-receiver:8000/health

   # For WebSocket, test upgrade
   curl -i -N -H "Connection: Upgrade" \
     -H "Upgrade: websocket" \
     http://cloud-receiver:8000/connect/stream/test-channel
   ```

4. **SSL/TLS certificate issues:**
   ```bash
   # Test with verbose SSL output
   curl -v https://cloud-receiver:8000/health

   # If using self-signed certs, configure connector to trust them
   # or disable verification (not recommended for production)
   ```

### Authentication Failures

**Symptoms:**
- `401 Unauthorized` or `4001` WebSocket close code
- "Invalid channel token" errors

**Solutions:**

1. **Check token matches between cloud and connector:**

   Cloud (`webhooks.json`):
   ```json
   {
       "my_relay": {
           "module": "webhook_connect",
           "module-config": {
               "channel": "my-channel",
               "channel_token": "secret_token_123"  // Must match!
           }
       }
   }
   ```

   Connector (`connector.json`):
   ```json
   {
       "routes": {
           "my-channel": {
               "token": "secret_token_123"  // Must match!
           }
       }
   }
   ```

2. **Check environment variable substitution:**
   ```bash
   # Ensure env vars are set
   echo $CHANNEL_TOKEN

   # If using {$VAR} syntax, ensure format is correct
   "token": "{$CHANNEL_TOKEN}"  # Correct
   "token": "$CHANNEL_TOKEN"    # Wrong - won't be substituted
   ```

3. **Check for token rotation:**
   ```bash
   # Query channel to see if token was rotated
   curl -s http://cloud:8000/admin/webhook-connect/channels/my-channel \
     -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.token_rotated_at'
   ```

### Channel Not Found

**Symptoms:**
- `4002` WebSocket close code
- "Channel does not exist" errors

**Solutions:**

1. **Verify channel is configured on cloud side:**
   ```bash
   curl -s http://cloud:8000/admin/webhook-connect/channels \
     -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.channels[].name'
   ```

2. **Check channel name matches exactly (case-sensitive):**
   ```json
   // Cloud: channel is "Stripe-Payments"
   // Connector must use exactly: "Stripe-Payments"
   // Not: "stripe-payments" or "STRIPE-PAYMENTS"
   ```

3. **Ensure webhook_connect module is loaded:**
   ```bash
   # Check logs for module registration
   docker logs cloud-receiver | grep "webhook_connect"
   ```

## Message Delivery Issues

### Messages Not Being Delivered

**Symptoms:**
- Webhooks sent to cloud but not received by connector
- Queue depth keeps growing

**Debugging Steps:**

1. **Check if messages are being queued:**
   ```bash
   curl -s http://cloud:8000/admin/webhook-connect/channels/my-channel \
     -H "Authorization: Bearer $ADMIN_TOKEN"
   ```

   Response:
   ```json
   {
       "stats": {
           "messages_queued": 150,    // Messages waiting
           "messages_in_flight": 5,   // Being processed
           "connected_clients": 0     // No connectors!
       }
   }
   ```

2. **Check connector is subscribed:**
   ```bash
   # Check connector logs
   docker logs connector | grep "Connected"

   # Should see:
   # [my-channel] Connected!
   ```

3. **Check Redis queue directly:**
   ```bash
   docker exec redis redis-cli
   > KEYS webhook_connect:*
   > XLEN webhook_connect:stream:my-channel
   ```

### Messages Delivered But Not Acknowledged

**Symptoms:**
- Messages keep being redelivered
- `delivery_count` increases
- Eventually messages go to dead letter queue

**Possible Causes:**

1. **Destination module failing:**
   ```bash
   # Check connector logs for errors
   docker logs connector | grep -i error

   # Common errors:
   # - Connection refused (destination unreachable)
   # - Authentication failed
   # - Timeout
   ```

2. **Connector crashing during processing:**
   ```bash
   # Check for OOM kills or crashes
   docker logs connector | tail -100
   dmesg | grep -i oom
   ```

3. **Processing taking too long:**
   ```json
   // Increase ACK timeout on cloud side
   {
       "module-config": {
           "channel": "my-channel",
           "ack_timeout_seconds": 60  // Default is 30
       }
   }
   ```

### Duplicate Messages

**Symptoms:**
- Same message processed multiple times
- Duplicate records in database

**Causes and Solutions:**

1. **At-least-once delivery is by design:**

   Messages may be redelivered if:
   - ACK is lost due to network issues
   - Connector crashes after processing but before ACK

   **Solution:** Make destinations idempotent
   ```sql
   -- Use upsert in PostgreSQL
   INSERT INTO events (id, data)
   VALUES ($1, $2)
   ON CONFLICT (id) DO NOTHING;
   ```

2. **Connector reconnecting during processing:**

   In-flight messages are returned to queue on disconnect.

   **Solution:** Use message deduplication
   ```json
   // Add message_id to payload for deduplication
   {
       "module-config": {
           "include_message_id": true
       }
   }
   ```

## Cloud Receiver Issues

### Webhook Connect Not Enabled

**Symptoms:**
- `/connect/stream` endpoints return 404
- Admin API not available

**Solution:**
```bash
# Ensure environment variable is set
export WEBHOOK_CONNECT_ENABLED=true

# Restart cloud receiver
docker-compose restart cloud-receiver
```

### Buffer Connection Failed

**Symptoms:**
- Cloud receiver fails to start
- "Failed to connect to buffer" errors

**Solutions:**

1. **Check Redis is running:**
   ```bash
   docker exec redis redis-cli ping
   # Should return: PONG
   ```

2. **Check Redis URL:**
   ```bash
   # Verify URL format
   export WEBHOOK_CONNECT_REDIS_URL=redis://host:6379/0

   # With authentication
   export WEBHOOK_CONNECT_REDIS_URL=redis://:password@host:6379/0
   ```

3. **Check RabbitMQ (if using):**
   ```bash
   # Test connection
   curl -u guest:guest http://rabbitmq:15672/api/healthchecks/node

   # Check URL format
   export WEBHOOK_CONNECT_RABBITMQ_URL=amqp://user:pass@host:5672/
   ```

### Queue Full

**Symptoms:**
- Webhook returns `503 Service Unavailable`
- `queue_full` error in response

**Solutions:**

1. **Increase queue size:**
   ```json
   {
       "module-config": {
           "channel": "my-channel",
           "max_queue_size": 50000  // Default is 10000
       }
   }
   ```

2. **Add more connectors to drain queue faster**

3. **Reduce message TTL to expire old messages:**
   ```json
   {
       "module-config": {
           "channel": "my-channel",
           "ttl_seconds": 3600  // 1 hour instead of 24
       }
   }
   ```

4. **Check why messages aren't being consumed:**
   - Are connectors connected?
   - Is processing too slow?
   - Are there destination errors?

## Connector Issues

### High Memory Usage

**Symptoms:**
- Connector using excessive memory
- OOM kills

**Solutions:**

1. **Reduce concurrency:**
   ```json
   {
       "concurrency": 5  // Reduce from default 10
   }
   ```

2. **Process smaller batches:**
   ```json
   {
       "module-config": {
           "batch_size": 10  // If module supports batching
       }
   }
   ```

3. **Check for memory leaks in destination modules**

### Processing Too Slow

**Symptoms:**
- Queue depth keeps growing
- High latency

**Solutions:**

1. **Increase concurrency:**
   ```json
   {
       "concurrency": 50  // Increase parallel processing
   }
   ```

2. **Use parallel execution for chains:**
   ```json
   {
       "chain-config": {
           "execution": "parallel"  // Instead of sequential
       }
   }
   ```

3. **Add more connector instances**

4. **Optimize destination modules:**
   - Use connection pooling
   - Batch inserts for databases
   - Async operations

### Connector Keeps Reconnecting

**Symptoms:**
- Frequent "Reconnecting..." messages
- Unstable connection

**Possible Causes:**

1. **Network instability:**
   - Check network quality
   - Increase keepalive intervals

2. **Cloud receiver overloaded:**
   - Scale up cloud receiver instances
   - Check resource usage

3. **Message processing errors:**
   - Check destination availability
   - Review error logs

4. **Heartbeat timeout:**
   ```bash
   # Check if heartbeats are being exchanged
   docker logs connector | grep heartbeat
   ```

## Debugging Tips

### Enable Debug Logging

**Cloud Receiver:**
```bash
export LOG_LEVEL=DEBUG
```

**Connector:**
```bash
python -m src.connector.main --config connector.json --log-level DEBUG
```

### Check Message Flow

```bash
# 1. Send test webhook
curl -X POST http://cloud:8000/webhook/my_relay \
  -H "Content-Type: application/json" \
  -d '{"test": "message"}'

# 2. Check queue
curl -s http://cloud:8000/admin/webhook-connect/channels/my-channel \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.stats'

# 3. Check connector logs
docker logs -f connector

# 4. Check destination
# (depends on module - check database, queue, etc.)
```

### Test Individual Components

```bash
# Test cloud receiver webhook endpoint
curl -v -X POST http://cloud:8000/webhook/my_relay \
  -H "Content-Type: application/json" \
  -d '{"test": "message"}'

# Test streaming API directly
curl -N http://cloud:8000/connect/stream/my-channel/sse \
  -H "Authorization: Bearer $CHANNEL_TOKEN"

# Test admin API
curl -s http://cloud:8000/admin/webhook-connect/channels \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

### Check Redis Directly

```bash
docker exec -it redis redis-cli

# List webhook connect keys
KEYS webhook_connect:*

# Check stream length
XLEN webhook_connect:stream:my-channel

# Read recent messages
XRANGE webhook_connect:stream:my-channel - + COUNT 5

# Check consumer groups
XINFO GROUPS webhook_connect:stream:my-channel
```

## Common Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| `invalid_channel_token` | Token mismatch | Verify tokens match between cloud and connector |
| `channel_not_found` | Channel not configured | Add webhook_connect config to webhooks.json |
| `max_connections` | Too many connectors | Increase `max_connections` or reduce connector count |
| `queue_full` | Buffer at capacity | Increase `max_queue_size` or add connectors |
| `buffer_error` | Redis/RabbitMQ issue | Check buffer service health |
| `ack_timeout` | Processing too slow | Increase timeout or optimize processing |
| `destination_unavailable` | Local service down | Check destination service health |

## Getting Help

If you're still stuck:

1. **Check the logs** with `LOG_LEVEL=DEBUG`
2. **Review the full configuration** for typos
3. **Test components individually** to isolate the issue
4. **Check GitHub issues** for similar problems
5. **Open a new issue** with:
   - Configuration (sanitized)
   - Error messages
   - Steps to reproduce
   - Environment details

## Related Documentation

- [Webhook Connect Overview](webhook-connect) - Architecture and concepts
- [Getting Started](webhook-connect-getting-started) - Basic setup guide
- [Advanced Configuration](webhook-connect-advanced) - Production deployment
