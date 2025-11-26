# Retry Mechanism Implementation Analysis

## Current State Analysis

### Module Execution Flow

1. **Current Flow** (`src/webhook.py:103`):
   ```python
   module = module_class(module_config)
   asyncio.create_task(module.process(payload, dict(self.headers.items())))
   ```
   - Modules are executed as fire-and-forget async tasks
   - No error handling or retry logic at the handler level
   - Errors are silently swallowed (task runs in background)
   - Webhook returns 200 OK immediately, regardless of module success
   - **Proposed**: Return 202 Accepted when destination is not working and retries are in progress

2. **Module Error Patterns**:
   - **Network errors**: RabbitMQ, Kafka, HTTP, WebSocket (connection failures, timeouts)
   - **Service unavailable**: External services down (RabbitMQ, Kafka, S3, ClickHouse)
   - **Authentication errors**: Invalid credentials, expired tokens
   - **Resource errors**: Queue full, disk full, S3 bucket issues
   - **Transient errors**: Temporary network glitches, rate limiting

3. **Current Error Handling**:
   - Most modules catch exceptions and re-raise them
   - WebSocket module has basic retry logic (3 attempts)
   - No centralized retry mechanism
   - No error logging/monitoring for failed module executions

## Design Options

### Option 1: Wrapper Function with Retry Logic (Recommended)

**Approach**: Create a retry wrapper that wraps module.process() calls

**Pros**:
- ✅ Non-invasive - doesn't require module changes
- ✅ Centralized retry logic
- ✅ Configurable per webhook
- ✅ Can add exponential backoff
- ✅ Can differentiate retryable vs non-retryable errors

**Cons**:
- ⚠️ Still fire-and-forget (webhook returns 202 Accepted when retries are in progress)
- ⚠️ Need to handle task tracking if we want to wait

**Implementation Location**: `src/webhook.py` or new `src/retry_handler.py`

### Option 2: BaseModule Retry Method

**Approach**: Add retry logic to BaseModule class

**Pros**:
- ✅ Modules can opt-in/opt-out
- ✅ Module-specific retry strategies possible

**Cons**:
- ❌ Requires changes to all modules
- ❌ Duplicates retry logic across modules
- ❌ Harder to maintain

### Option 3: Background Retry Queue (Advanced)

**Approach**: Failed executions go to a retry queue (Redis/RabbitMQ), separate worker retries

**Pros**:
- ✅ Survives application restarts
- ✅ Can retry hours/days later
- ✅ Can monitor retry queue
- ✅ Scales independently

**Cons**:
- ❌ Complex implementation
- ❌ Requires additional infrastructure
- ❌ Overkill for simple transient failures

## Recommended Approach: Hybrid (Option 1 + Enhanced)

### Phase 1: Immediate Retry Wrapper
- Implement retry wrapper in `src/webhook.py`
- Configurable retries per webhook
- Exponential backoff
- Error classification (retryable vs non-retryable)

### Phase 2: Optional Background Queue (Future)
- For critical webhooks, optionally send failures to retry queue
- Separate retry worker processes them later

## Implementation Design

### 1. Configuration Schema

```json
{
  "webhook_id": {
    "data_type": "json",
    "module": "rabbitmq",
    "retry": {
      "enabled": true,
      "max_attempts": 3,
      "initial_delay": 1.0,
      "max_delay": 60.0,
      "backoff_multiplier": 2.0,
      "retryable_errors": [
        "ConnectionError",
        "TimeoutError",
        "ServiceUnavailable"
      ],
      "non_retryable_errors": [
        "AuthenticationError",
        "ValidationError",
        "PermissionDenied"
      ]
    }
  }
}
```

### 2. Retry Handler Class

```python
# src/retry_handler.py
class RetryHandler:
    async def execute_with_retry(
        self,
        func: Callable,
        *args,
        retry_config: Dict = None,
        **kwargs
    ) -> Tuple[bool, Optional[Exception]]:
        """
        Execute function with retry logic.
        
        Returns:
            (success: bool, last_error: Optional[Exception])
        """
```

### 3. Error Classification

**Retryable Errors** (default):
- Connection errors (ConnectionError, ConnectionRefusedError)
- Timeout errors (TimeoutError, asyncio.TimeoutError)
- Network errors (httpx.NetworkError, aio_pika exceptions)
- Service unavailable (503, 502)
- Rate limiting (429) - with longer backoff

**Non-Retryable Errors** (fail immediately):
- Authentication errors (401, 403)
- Validation errors (400, 422)
- Not found errors (404)
- Permission errors
- Configuration errors

### 4. Backoff Strategies

**Exponential Backoff** (recommended):
```
delay = min(initial_delay * (backoff_multiplier ^ attempt), max_delay)
```

**Fixed Delay**:
```
delay = initial_delay
```

**Linear Backoff**:
```
delay = initial_delay * attempt
```

## Implementation Details

### File Structure

```
src/
├── retry_handler.py          # New: Retry logic
├── webhook.py                 # Modified: Use retry handler
└── modules/
    └── base.py                # Optional: Add retry hooks
```

### Key Components

1. **RetryHandler** (`src/retry_handler.py`):
   - `execute_with_retry()` - Main retry logic
   - `is_retryable_error()` - Error classification
   - `calculate_backoff()` - Backoff calculation
   - `log_retry_attempt()` - Logging

2. **WebhookHandler Changes** (`src/webhook.py`):
   - Check for retry config
   - Wrap module.process() with retry handler
   - Handle retry results (log, metrics)

3. **Error Classification**:
   - Map exception types to retryable/non-retryable
   - Handle HTTP status codes
   - Handle module-specific errors

### Code Flow

```
Webhook Request
    ↓
Validation (no retries)
    ↓
process_webhook()
    ↓
Check retry config
    ↓
RetryHandler.execute_with_retry(module.process)
    ↓
Attempt 1 → Success? → Return 200 OK
    ↓ Failure
Wait (backoff)
    ↓
Attempt 2 → Success? → Return 200 OK
    ↓ Failure
Wait (backoff)
    ↓
Attempt 3 → Success? → Return 200 OK
    ↓ Failure
Log final failure
Return 202 Accepted (processing in background, retries exhausted)
```

**HTTP Status Code Strategy**:
- **200 OK**: Module execution succeeded (immediate or after retry)
- **202 Accepted**: Module execution failed but retries are configured and will continue in background
- **500 Internal Server Error**: Only if validation fails or critical system error (not module execution)

## Configuration Examples

### Basic Retry (3 attempts, exponential backoff)
```json
{
  "rabbitmq_webhook": {
    "data_type": "json",
    "module": "rabbitmq",
    "queue_name": "events",
    "retry": {
      "enabled": true,
      "max_attempts": 3
    }
  }
}
```

### Advanced Retry Configuration
```json
{
  "critical_webhook": {
    "data_type": "json",
    "module": "kafka",
    "topic": "critical_events",
    "retry": {
      "enabled": true,
      "max_attempts": 5,
      "initial_delay": 2.0,
      "max_delay": 120.0,
      "backoff_multiplier": 2.0,
      "retryable_errors": [
        "ConnectionError",
        "TimeoutError",
        "KafkaError"
      ]
    }
  }
}
```

### No Retry (explicit)
```json
{
  "no_retry_webhook": {
    "data_type": "json",
    "module": "log",
    "retry": {
      "enabled": false
    }
  }
}
```

## Edge Cases & Considerations

### 1. Task Lifecycle & HTTP Status Codes
- **Current**: Tasks run in background, webhook returns 200 OK immediately
- **With Retries**: 
  - If module succeeds (immediate or after retry): Return **200 OK**
  - If module fails but retries are configured: Return **202 Accepted** (processing continues in background)
  - If module fails with non-retryable error: Return **202 Accepted** (indicates request accepted but processing failed)
- **Consideration**: 202 Accepted properly indicates asynchronous processing, which is semantically correct for background retries

### 2. Memory & Resource Usage
- **Risk**: Many failed webhooks = many retry tasks running
- **Mitigation**: 
  - Limit concurrent retries
  - Use task groups
  - Add circuit breaker pattern

### 3. Duplicate Processing
- **Risk**: Retry succeeds after original also succeeded
- **Mitigation**: 
  - Idempotent modules (most should be)
  - Add idempotency keys if needed

### 4. Logging & Monitoring
- **Need**: Log retry attempts, failures, success after retry
- **Metrics**: 
  - Retry count per webhook
  - Success rate after retry
  - Average retry delay

### 5. Module-Specific Considerations

**RabbitMQ**:
- Connection pool already handles some retries
- May need to retry at module level for queue full scenarios

**Kafka**:
- Producer has built-in retries
- Module-level retry for producer initialization failures

**HTTP**:
- Network errors: retryable
- 4xx errors: non-retryable
- 5xx errors: retryable

**S3**:
- Network errors: retryable
- Permission errors: non-retryable
- Bucket errors: non-retryable

**WebSocket**:
- Already has retry logic
- May want to disable module retry if using wrapper

## Testing Strategy

### Unit Tests
- RetryHandler logic
- Error classification
- Backoff calculation
- Configuration parsing

### Integration Tests
- Retry with failing RabbitMQ
- Retry with failing HTTP endpoint
- Retry with transient errors
- Non-retryable error handling

### Test Scenarios
1. **Transient failure → Success**: Verify retry succeeds
2. **All retries fail**: Verify proper logging
3. **Non-retryable error**: Verify immediate failure
4. **Configuration disabled**: Verify no retries
5. **Backoff timing**: Verify delays are correct

## Metrics & Observability

### Metrics to Track
- `webhook_retry_attempts_total` - Counter
- `webhook_retry_success_total` - Counter
- `webhook_retry_failure_total` - Counter
- `webhook_retry_duration_seconds` - Histogram

### Logging
- INFO: Retry attempt started
- WARNING: Retry attempt failed, will retry
- ERROR: All retries exhausted
- INFO: Retry succeeded after N attempts

### HTTP Response Codes
- **200 OK**: Module execution succeeded (immediate success or after successful retry)
- **202 Accepted**: 
  - Module execution failed but retries are configured (will continue in background)
  - Indicates request was accepted but processing is not yet complete
  - Client should not resend the request
- **500 Internal Server Error**: Only for critical system errors (validation failures, configuration errors)

## Implementation Phases

### Phase 1: Core Retry Mechanism (MVP)
- [ ] Create `RetryHandler` class
- [ ] Basic retry logic with exponential backoff
- [ ] Error classification
- [ ] Integration with `WebhookHandler`
- [ ] Configuration parsing
- [ ] HTTP status code handling (200 OK for success, 202 Accepted for retries in progress)
- [ ] Unit tests

### Phase 2: Enhanced Features
- [ ] Custom retryable error lists
- [ ] Different backoff strategies
- [ ] Retry metrics/logging
- [ ] Integration tests

### Phase 3: Advanced Features (Future)
- [ ] Circuit breaker pattern
- [ ] Background retry queue
- [ ] Retry dashboard/monitoring
- [ ] Dead letter queue for permanent failures

## Recommended Defaults

```python
DEFAULT_RETRY_CONFIG = {
    "enabled": False,  # Opt-in by default
    "max_attempts": 3,
    "initial_delay": 1.0,  # seconds
    "max_delay": 60.0,  # seconds
    "backoff_multiplier": 2.0,
    "retryable_errors": [
        "ConnectionError",
        "ConnectionRefusedError",
        "TimeoutError",
        "asyncio.TimeoutError",
        "httpx.NetworkError",
        "httpx.ConnectError",
        "httpx.ReadTimeout",
        "aio_pika.exceptions.AMQPConnectionError",
        "aiokafka.errors.KafkaError"
    ],
    "non_retryable_errors": [
        "AuthenticationError",
        "PermissionError",
        "ValueError",
        "KeyError"
    ]
}
```

## HTTP Status Code Implementation

### Response Logic

```python
# In src/webhook.py or src/main.py

async def process_webhook_with_retry(self):
    """Process webhook with retry logic and appropriate HTTP status codes."""
    payload, headers = await self.process_webhook()
    
    # Get module and execute with retry
    module = module_class(module_config)
    retry_config = self.config.get("retry", {})
    
    if retry_config.get("enabled", False):
        # Execute with retry handler
        success, error = await retry_handler.execute_with_retry(
            module.process,
            payload,
            dict(self.headers.items()),
            retry_config=retry_config
        )
        
        if success:
            return JSONResponse(
                content={"message": "200 OK", "status": "processed"},
                status_code=200
            )
        else:
            # Retries configured but all failed
            # Return 202 Accepted to indicate request accepted, processing continues
            return JSONResponse(
                content={
                    "message": "202 Accepted",
                    "status": "accepted",
                    "note": "Request accepted, processing in background with retries"
                },
                status_code=202
            )
    else:
        # No retry configured, execute normally
        asyncio.create_task(module.process(payload, dict(self.headers.items())))
        return JSONResponse(
            content={"message": "200 OK"},
            status_code=200
        )
```

### Status Code Summary

| Scenario | HTTP Status | Description |
|----------|-------------|-------------|
| Module succeeds immediately | 200 OK | Request processed successfully |
| Module succeeds after retry | 200 OK | Request processed successfully after retry |
| Module fails, retries configured | 202 Accepted | Request accepted, retries will continue in background |
| Module fails, no retries | 200 OK | Request accepted (current behavior, no change) |
| Validation fails | 400/401/404 | Client error, no retry |
| System error | 500 | Server error, no retry |

## Next Steps

1. **Review & Approve Design**: Confirm approach meets requirements
2. **Implement Phase 1**: Core retry mechanism
3. **Test Thoroughly**: Unit + integration tests
4. **Document**: Update README with retry configuration
5. **Monitor**: Add metrics/logging in production
6. **Iterate**: Enhance based on real-world usage

