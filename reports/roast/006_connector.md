# Code Roast: src/connector

**Reviewed:** 2026-02-06
**Target:** `src/connector/` (5 files: main.py, config.py, stream_client.py, processor.py, __init__.py)
**Reviewer:** Claude (Senior Engineer Mode)

---

## 1. Review Summary

Top-impact issues:

- **SSE parser silently drops multi-line `data:` fields**, losing webhook payloads that span multiple lines (breaks SSE spec RFC 8895)
- **BatchProcessor creates a new aiohttp session per message** -- under load this is a resource bomb that will exhaust file descriptors
- **Config env-override logic has inverted precedence** -- env vars matching the default value are silently ignored, even when the file config differs
- **SSE client has no heartbeat timeout** -- a stalled server hangs the connector forever with `timeout=None`
- **Channel name injected unsanitized into URL path** -- `../admin/reload-config` as a channel name is a path traversal vector
- **`_create_ssl_context()` returns `False` (a bool)** violating its `Optional[ssl.SSLContext]` return type

---

## 2. Top Issues Table (Prioritized)

| Done | Severity | Location | Category | Description |
|------|----------|----------|----------|-------------|
| [x] | P0 | stream_client.py:359-360 | Correctness | SSE parser drops multi-line data fields, corrupting payloads |
| [x] | P0 | processor.py:460-468 | Performance | BatchProcessor creates new session+processor per message |
| [x] | P1 | config.py:237-241 | Correctness | Env override ignores env vars that match default, not file config |
| [x] | P1 | stream_client.py:292-398 | Reliability | SSE client has no heartbeat monitor (hangs forever on stalled server) |
| [x] | P1 | config.py:290-309 | Security | Channel name unsanitized in URL path -- path traversal possible |
| [x] | P1 | processor.py:297-304 | Security | Processor ignores ca_cert_path/client_cert_path, uses bare bool for SSL |
| [x] | P1 | main.py:209 | Security | `--token` CLI arg visible in process list (`ps aux`) |
| [x] | P2 | stream_client.py:123-126 | Maintainability | `_create_ssl_context()` returns `False` (bool), violates type signature |
| [x] | P2 | stream_client.py:104-111 | Reliability | Reconnect backoff has no jitter -- thundering herd after outage |
| [x] | P2 | config.py:140-142 | Correctness | `from_dict` uses raw `setattr` with no type validation |
| [x] | P2 | processor.py:363 | Reliability | BatchProcessor queue is unbounded -- OOM under backpressure |
| [ ] | P2 | stream_client.py:399-456,554-612 | Maintainability | ACK/NACK methods copy-pasted across 3 client classes |
| [x] | P3 | main.py:319-335 | Observability | Startup banner uses `print()` not `logger.info()` |
| [x] | P3 | processor.py:322-329 | Maintainability | ProcessingStats tracks `messages_retried` but never increments it |

---

## 3. Detailed Findings

### [P0] stream_client.py:359-360 -- SSE Parser Drops Multi-Line Data (Correctness)

**Problem:** The SSE parser overwrites `event_data` on each `data:` line instead of appending:

```python
elif line.startswith("data:"):
    event_data = line[5:].strip()  # OVERWRITES, doesn't append
```

Per the [SSE specification](https://html.spec.whatwg.org/multipage/server-sent-events.html#event-stream-interpretation), multiple `data:` lines in a single event should be concatenated with `\n`. Example:

```
event: webhook
data: {"id": "123",
data:  "payload": "large value"}

```

This connector receives only `" \"payload\": \"large value\"}"` -- the first line is silently dropped. The resulting `json.loads()` fails, and the webhook is lost with only an error log.

**Risk:** Any webhook payload that the cloud server serializes across multiple `data:` lines is silently corrupted or lost. This will page you at 3am when a large payload arrives and your connector starts dropping every message.

**Fix:**
```python
elif line.startswith("data:"):
    if event_data:
        event_data += "\n" + line[5:].strip()
    else:
        event_data = line[5:].strip()
```

---

### [P0] processor.py:460-468 -- BatchProcessor Session Bomb (Performance)

**Problem:** `_process_batch()` creates a brand new `MessageProcessor` (with its own `aiohttp.ClientSession`) for every single message:

```python
for msg in messages:
    processor = MessageProcessor(
        self.config, self.ack_callback, self.nack_callback
    )
    await processor.start()    # Opens new aiohttp session
    try:
        await processor.process(msg)
    finally:
        await processor.stop() # Closes session
```

For a batch of 10 messages, this opens and closes 10 TCP connections. Under load with 100 messages/second, you exhaust file descriptors in minutes.

**Risk:** `OSError: [Errno 24] Too many open files` under any meaningful load. The whole point of batching is efficiency -- this is slower than no batching.

**Fix:** Share a single `MessageProcessor` instance across the batch lifecycle. Or better: the `BatchProcessor` TODO on line 458 says "Implement batch delivery" -- this entire class is incomplete scaffolding that should not be used in production.

---

### [P1] config.py:237-241 -- Env Override Compares Against Wrong Baseline (Correctness)

**Problem:** `load()` merges env vars by comparing against `cls()` defaults, not against the file config:

```python
env_value = getattr(env_config, field_name)
default_value = getattr(cls(), field_name)        # <-- compares to CLASS default
if env_value != default_value:
    setattr(config, field_name, env_value)
```

**Scenario:** File sets `reconnect_delay: 5.0`. User sets `CONNECTOR_RECONNECT_DELAY=1.0` to override back to 1 second. Because `1.0` equals the class default, the env var is silently ignored. The connector uses `5.0`.

**Risk:** Users cannot override file config values back to their defaults via env vars. Debugging this is miserable because the config "looks right" in the env but the connector behaves differently.

**Fix:** Track which env vars were actually set (check `os.environ.get()` is not None) rather than comparing values:
```python
for env_var, field_info in env_mapping.items():
    if os.environ.get(env_var) is not None:
        setattr(config, field_name, converted_value)
```

---

### [P1] stream_client.py:292-398 -- SSE Client Missing Heartbeat Monitor (Reliability)

**Problem:** `WebSocketClient` has `_monitor_heartbeat()` (line 246-261) that detects stalled connections and closes the socket. `SSEClient` has nothing equivalent. Combined with `timeout=None` on line 315:

```python
timeout=aiohttp.ClientTimeout(total=None),  # No timeout for SSE
```

If the server stops sending heartbeats (network partition, server crash without TCP RST), the SSE client blocks on `response.content.iter_any()` indefinitely. No reconnection ever happens.

**Risk:** Silent permanent hang. The connector appears running but receives zero messages. You find out from your users, not your monitoring.

**Fix:** Port `_monitor_heartbeat()` from `WebSocketClient` to `SSEClient`. Start it as a background task in `connect()`, have it close `self._response` on timeout.

---

### [P1] config.py:290-309 -- Channel Name Path Traversal (Security)

**Problem:** `get_stream_url()` interpolates `self.channel` directly into the URL path with zero sanitization:

```python
return f"{ws_url}/connect/stream/{self.channel}"
```

`self.channel` is user-supplied (config file, env var, or CLI arg). A channel name like `../../admin/reload-config?token=x` constructs:
```
wss://host/connect/stream/../../admin/reload-config?token=x
```

**Risk:** Path traversal against the cloud server. Depending on the server's routing, this could hit admin endpoints, other channels, or internal APIs.

**Fix:** Validate channel name in `validate()` -- restrict to `[a-zA-Z0-9_-]`:
```python
import re
if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_-]*$', self.channel):
    errors.append("channel must contain only alphanumeric characters, hyphens, and underscores")
```
Also URL-encode the channel in `get_stream_url()` as defense-in-depth.

---

### [P1] processor.py:297-304 -- Processor Ignores TLS Config (Security)

**Problem:** `_deliver()` passes `ssl=self.config.verify_ssl` (a bare `bool`) to aiohttp:

```python
async with self._session.request(
    ...
    ssl=self.config.verify_ssl,  # True or False, never SSLContext
) as response:
```

`ConnectorConfig` has `ca_cert_path`, `client_cert_path`, and `client_key_path` fields. `StreamClient._create_ssl_context()` builds a proper `SSLContext` from these. But `MessageProcessor` never calls `_create_ssl_context()` -- it ignores these fields entirely.

**Risk:** Users who configure mutual TLS or custom CA bundles for their cloud connection will find that webhook delivery to local targets silently falls back to default system CAs. mTLS auth to local targets is broken.

**Fix:** Build an SSL context in `MessageProcessor.start()` using the same logic as `StreamClient._create_ssl_context()`, and pass it to requests.

---

### [P1] main.py:209 -- Token Visible in Process List (Security)

**Problem:** `--token secret123` is a CLI argument, visible to any user on the system via `ps aux`, `/proc/PID/cmdline`, or `htop`.

**Risk:** Token exposure on shared hosts. The env var path (`CONNECTOR_TOKEN`) is safer, but the CLI arg is documented as the primary usage pattern in the epilog (line 190-191).

**Fix:** Remove `--token` or read it from stdin/file. At minimum, add a warning in `--help` and prefer `CONNECTOR_TOKEN` env var. Consider `--token-file` instead.

---

### [P2] stream_client.py:123-126 -- Type Lie in SSL Context (Maintainability)

**Problem:**
```python
def _create_ssl_context(self) -> Optional[ssl.SSLContext]:
    if not self.config.verify_ssl:
        return False  # type: ignore if this existed
```

Return type says `Optional[ssl.SSLContext]`, actual return is `False`. This works because aiohttp's `ssl` parameter accepts `bool | SSLContext | None`, but any code that treats the return value as an `SSLContext` will crash at runtime. mypy would flag this.

**Fix:** Change return type to `Optional[ssl.SSLContext | bool]`, or better: have aiohttp callers handle `verify_ssl=False` separately instead of mixing types.

---

### [P2] stream_client.py:104-111 -- Reconnect Backoff Has No Jitter (Reliability)

**Problem:**
```python
self._reconnect_delay = min(
    self._reconnect_delay * self.config.reconnect_backoff_multiplier,
    self.config.max_reconnect_delay,
)
```

Deterministic backoff means all connectors reconnect at the exact same intervals after an outage.

**Risk:** Thundering herd on the cloud server when it comes back up. 100 connectors all reconnect at t=1s, t=2s, t=4s, etc.

**Fix:** Add jitter:
```python
import random
jitter = random.uniform(0, self._reconnect_delay * 0.3)
await asyncio.sleep(self._reconnect_delay + jitter)
```

---

### [P2] config.py:140-142 -- from_dict Trusts Input Types (Correctness)

**Problem:**
```python
for field_name in simple_fields:
    if field_name in data:
        setattr(config, field_name, data[field_name])
```

No type validation. `{"reconnect_delay": "banana"}` sets `config.reconnect_delay = "banana"`. This won't fail until `asyncio.sleep("banana")` is called at runtime.

**Risk:** Delayed failures that are hard to trace back to config parsing.

**Fix:** Validate types against field annotations, or at minimum coerce known numeric fields.

---

### [P2] processor.py:363 -- Unbounded BatchProcessor Queue (Reliability)

**Problem:**
```python
self._queue: asyncio.Queue = asyncio.Queue()  # No maxsize
```

If message production outpaces consumption, memory grows without limit.

**Risk:** OOM under sustained load with a slow target. Same issue as the ClickHouse analytics queue in the main module.

**Fix:** `asyncio.Queue(maxsize=1000)` with backpressure handling.

---

### [P2] stream_client.py -- ACK/NACK Copy-Paste x3 (Maintainability)

**Problem:** `send_ack()` and `send_nack()` are copy-pasted identically across `SSEClient` (lines 399-456) and `LongPollClient` (lines 554-612). The only difference is `LongPollClient` passes `ssl=self._ssl_context`.

**Risk:** Bug fixes applied to one client but not the others. This is already partially happening -- `LongPollClient.send_ack` passes `ssl=self._ssl_context` while `SSEClient.send_ack` doesn't pass `ssl` at all.

**Fix:** Move HTTP-based ACK/NACK into the base `StreamClient` class or a mixin. WebSocket overrides with its own WS-based implementation.

---

### [P3] main.py:319-335 -- Startup Banner via print() (Observability)

**Problem:** The ASCII art banner and startup info use `print()` instead of `logger.info()`. If stdout is redirected or a JSON log formatter is configured, the banner bypasses structured logging entirely.

**Fix:** Use `logger.info()` or at minimum write to stderr.

---

### [P3] processor.py:328 -- Dead Stats Field (Maintainability)

**Problem:**
```python
@dataclass
class ProcessingStats:
    messages_retried: int = 0    # Never incremented anywhere
    total_delivery_time_ms: float = 0.0  # Never updated anywhere
```

Two of four stats fields are always zero. Dead fields suggest incomplete implementation or abandoned feature work.

**Fix:** Either wire up the stats or remove the dead fields.

---

## 4. Configuration & Standards Violations

| Location | Value/Pattern | Issue | Fix |
|----------|---------------|-------|-----|
| config.py:140-142 | `setattr(config, field_name, data[field_name])` | No type validation on config input | Add type coercion/validation |
| config.py:186 | `converter(value)` | No error handling on env var conversion | Wrap in try/except with clear message |
| config.py:57-59 | `cloud_url: str = ""` | Empty string defaults for required fields | Use `Optional[str] = None` or sentinel |
| config.py:267 | `protocol not in ["websocket", "sse", "long_poll"]` | Validation uses magic strings | Use an Enum |
| main.py:209 | `--token` CLI arg | Secrets in process argument list | Use `--token-file` or env var only |
| stream_client.py:468 | `self._poll_timeout = 30` | Hardcoded magic number | Move to config |

---

## 5. Security Concerns

1. **Token in CLI args** (P1): `--token` visible in `ps aux`. Prefer env var or file.
2. **No cloud_url validation** (P2): No SSRF protection on `cloud_url`. Unlike the main webhook module which blocks private IPs and metadata endpoints, the connector accepts any URL scheme including `file://`, `ftp://`, etc.
3. **Channel path traversal** (P1): Channel name interpolated directly into URL with no sanitization. `../` sequences can target other paths.
4. **No TLS on delivery** (P1): Processor ignores `ca_cert_path`/`client_cert_path` when delivering to local targets. mTLS configuration is silently broken.
5. **SSE ACK sends auth token without SSL context**: `SSEClient.send_ack()` sends the Bearer token but doesn't pass SSL context (unlike `LongPollClient`). If the SSL context was configured for certificate pinning, ACK requests bypass it.

---

## 6. Observability Gaps

Missing observability elements:
- [ ] Structured logging -- uses f-strings with basic `logging`, no JSON formatter option
- [ ] Metrics/counters -- `ProcessingStats` exists but 2/4 fields are dead; no Prometheus/StatsD export
- [ ] Distributed tracing -- `X-Webhook-Message-ID` header is set but no OpenTelemetry/trace context propagation
- [ ] Correlation IDs -- no request-level correlation between stream receive and delivery
- [ ] Health endpoint -- `get_status()` exists but is not exposed via HTTP; only accessible programmatically
- [ ] Reconnection metrics -- no counter for reconnection attempts, failures, or time-in-disconnected-state

---

## 7. Test & Verification Notes

- **Config-only test coverage**: `test_webhook_connect_connector.py` tests only `ConnectorConfig` and `TargetConfig` (363 lines, config parsing only)
- **Zero tests for**: `StreamClient`, `WebSocketClient`, `SSEClient`, `LongPollClient`, `MessageProcessor`, `BatchProcessor`, `LocalConnector`
- **The SSE parser bug (P0) has no test** -- a single test with multi-line `data:` fields would have caught it
- **No async tests at all** -- all tests are synchronous, testing only dataclass behavior
- **No mock-based delivery tests** -- `_deliver()`, `_deliver_with_retry()`, ACK/NACK flows are untested
- **No reconnection tests** -- the entire reconnection state machine is untested

---

## 8. Quick Wins

1. **Fix the SSE parser** (5 min) -- change `event_data = line[5:]...` to append with `\n` separator
2. **Add channel name validation** (5 min) -- regex check in `validate()`
3. **Add jitter to reconnect backoff** (5 min) -- `random.uniform(0, delay * 0.3)`
4. **Port heartbeat monitor to SSEClient** (15 min) -- copy from WebSocketClient, adapt for SSE
5. **Extract HTTP ACK/NACK to base class** (15 min) -- eliminates 120 lines of duplication
6. **Delete or gate BatchProcessor** (2 min) -- it's broken scaffolding with a TODO; don't ship it
7. **Add `maxsize` to BatchProcessor queue** (1 min)

---

*Generated by Claude Code /roast command*
