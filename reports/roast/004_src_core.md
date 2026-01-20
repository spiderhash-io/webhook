# Code Roast: Core Webhook Module (src/)

**Reviewed:** 2026-01-20
**Target:** ./src/
**Reviewer:** Claude (Senior Engineer Mode)

---

## 1. Review Summary

Top-impact issues (max 5 bullets):
- **FIXED: Event Loop Blocking:** Synchronous `json.loads` moved to background thread via `asyncio.to_thread`.
- **FIXED: Resource Leaks:** `cleanup_task` now properly tracked and cancelled in shutdown handler.
- **FIXED: Credential Sanitization Overhead:** Removed redundant `deepcopy` calls; `CredentialCleaner` now handles creation of new structure efficiently.
- **FIXED: Redis Stats Overhead:** Consolidated multiple Redis increments and expirations into a single atomic Lua script (reducing 8+ round-trips to 1). Moved individual total counters into a single Redis Hash to reduce key namespace pollution.

---

## 2. Top Issues Table (Prioritized)

| Done | Severity | Location | Category | Description |
|------|----------|----------|----------|-------------|
| [x] | P0 | webhook.py:434 | Performance | Blocking `json.loads` on main event loop. |
| [x] | P1 | main.py:551-559 | Reliability | `cleanup_task` is an infinite loop that leaks on every reload/test run. |
| [x] | P1 | webhook.py:507 | Performance | `copy.deepcopy` on every payload for sanitization. |
| [ ] | P2 | main.py:393-398 | Security | CORS logic warns about `localhost` but allows it, risking CSRF in dev-turned-prod. |
| [x] | P2 | webhook.py:238-252 | Maintainability | Instantiating 13 validators for *every* request, regardless of config. |
| [x] | P3 | utils.py:649-673 | Performance | Redis stats use a pipeline but increment 3 separate keys for every hit. |

---

## 3. Detailed Findings

### [P0] webhook.py:434 – Blocking JSON Parsing (Performance)

**Problem:** `payload = json.loads(decoded_body)` is a synchronous operation. 

**Risk:** For large JSON payloads (common in webhooks), this blocks the entire FastAPI event loop. A single 10MB payload will pause the world for all other concurrent requests.

**Reproduction:** Send a large, nested JSON array. Watch the `p99` latency of unrelated health check endpoints skyrocket.

**Fix:**
- Use `anyio.to_thread.run_sync(json.loads, decoded_body)` or a faster library like `orjson`.

---

### [P1] main.py:551-559 – Orphaned Background Tasks (Reliability)

**Problem:** `cleanup_task` is started as a fire-and-forget task and has no cancellation logic.

**Risk:** When the application shuts down or reloads, the old `cleanup_task` keeps running in the background. If you trigger multiple hot reloads, you'll have N cleanup tasks competing for the same resources and logging noise.

**Reproduction:** Start the app, trigger `/admin/reload-config` multiple times, and check your task list or logs.

**Fix:**
- Store the task in `app.state.cleanup_task`.
- In `shutdown_logic`, call `app.state.cleanup_task.cancel()` and `await app.state.cleanup_task` (handling the cancellation exception).

---

### [P1] webhook.py:507 – Deepcopy for Sanitization (Performance)

**Problem:** `cleaned_payload = cleaner.clean_credentials(copy.deepcopy(payload))` is called for every request where cleanup is enabled.

**Risk:** `deepcopy` is notoriously slow in Python. For a high-throughput webhook receiver, this is your primary CPU bottleneck. It also doubles memory pressure for every request.

**Fix:**
- Implement a lazy-cleaning approach or a non-recursive mask that doesn't require a full deep copy of non-sensitive branches.
- Or, better yet, only clean the payload if the destination module *actually* needs it (e.g., logging).

---

### [P2] main.py:83 – Fragile Fallback Logic (Reliability)

**Problem:** `ConfigManager` failure defaults to "legacy config loading."

**Risk:** This creates a split-brain scenario. If `ConfigManager` fails because of a valid file issue, falling back to an older, potentially out-of-date global variable `webhook_config_data` means your app is running on "ghost" settings that don't match the filesystem.

**Fix:**
- Fail fast. If the configuration manager cannot initialize, the service is not in a known good state and should refuse to start.

---

## 4. Configuration & Standards Violations

| Location | Value/Pattern | Issue | Fix |
|----------|---------------|-------|-----|
| main.py:209 | `os.getenv("PORT", "8000")` | Hardcoded default in logic | Move to `config.py` |
| utils.py:33 | `print(f"ERROR: {error_str}")` | Using `print` instead of structured logger | Use `logging.getLogger` |
| main.py:432 | `max_age=600` | Hardcoded CORS cache | Make configurable via env |

---

## 5. Security Concerns

- **Sensitive Info in Logs:** `main.py:636` prints `Connected to {host}:{port}/{database}`. Even with "sanitization," exposing internal DB structure and hostnames in stdout is a gift to an attacker who gains read access to logs.
- **CORS Localhost:** Allowing `localhost` in CORS (`main.py:395`) is dangerous. A malicious site in a user's browser could hit your local development webhook server.
- **Validator Overhead:** Every request triggers the construction of 13 validator objects. While mostly lightweight, this is unnecessary allocation and garbage collection pressure.

---

## 6. Observability Gaps

Missing observability elements:
- [x] Structured logging (Current: using `print`)
- [ ] Metrics/counters (Current: Redis-based, but not exported via Prometheus/OpenMetrics)
- [ ] Distributed tracing (No OpenTelemetry integration found)
- [ ] Correlation IDs (Request IDs are not propagated through the module chain)
- [x] Error reporting (Sanitization is present, but no Sentry/Honeybadger integration)

---

## 7. Test & Verification Notes

- **Task Leaks:** Tests likely leave background tasks running, which can cause flaky failures in CI if tasks from previous tests interfere with state.
- **Integration Heavy:** The codebase relies heavily on external services (Redis, ClickHouse) for even basic functionality, making local "unit" testing difficult without complex mocking.

---

## 8. Quick Wins

1. Replace `copy.deepcopy` in `CredentialCleaner` with a shallow-copy-on-write pattern.
2. Replace `print` with a proper `logging` setup to allow log level control (silencing DB connection noise).
3. Use `anyio` for blocking operations like JSON parsing and file writes.

---

*Generated by Claude Code /roast command*
