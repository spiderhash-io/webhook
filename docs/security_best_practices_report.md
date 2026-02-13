# Security Best Practices Report

## Executive Summary
I found **3 concrete security issues** that are present in code paths today. Two issues are **default-to-open admin/statistics endpoints** when environment variables are unset, and one issue is **authentication tokens accepted via URL query parameters** in Webhook Connect endpoints (token leakage risk). These are not theoretical; they are directly observable in the current code and can be verified by configuration state.

---

## High Severity

### 1) Admin endpoints are unauthenticated when `CONFIG_RELOAD_ADMIN_TOKEN` is unset
- **Rule ID:** FASTAPI-AUTH-001
- **Severity:** High
- **Location:** `src/main.py:1352-1627` (admin endpoints `/admin/reload-config`, `/admin/config-status`)
- **Evidence:**
  - `admin_token = os.getenv("CONFIG_RELOAD_ADMIN_TOKEN", "").strip()`
  - Auth checks are only enforced when `admin_token` is truthy; if it is empty, no auth check occurs. (`src/main.py:1371-1407`, `src/main.py:1591-1627`)
- **Impact:** Anyone who can reach the service can call admin endpoints to reload configuration and read configuration status when the env var is missing, leading to unauthorized operational control.
- **Fix:** Require authentication unconditionally for admin endpoints, or fail startup if `CONFIG_RELOAD_ADMIN_TOKEN` is missing in non-dev environments. At minimum, add a hard “deny unless configured” guard.
- **Mitigation:** Restrict `/admin/*` routes at the edge (reverse proxy or ingress) until enforced in-app.
- **False positive notes:** If `CONFIG_RELOAD_ADMIN_TOKEN` is always set in production deployments (and verified), this issue is mitigated. The code path is still open by default if the env var is absent.

---

## Medium Severity

### 2) `/stats` endpoint is unauthenticated when `STATS_AUTH_TOKEN` is unset
- **Rule ID:** FASTAPI-AUTH-001
- **Severity:** Medium
- **Location:** `src/main.py:1269-1349` (`/stats` endpoint)
- **Evidence:**
  - `stats_auth_token = os.getenv("STATS_AUTH_TOKEN", "").strip()` and auth check only runs if the token is set. (`src/main.py:1282-1301`)
  - Without auth, the endpoint returns `stats_data` which includes webhook IDs unless `STATS_SANITIZE_IDS=true`. (`src/main.py:1335-1349`)
- **Impact:** Unauthenticated users can enumerate webhook IDs and usage statistics, which can aid endpoint discovery and traffic analysis.
- **Fix:** Require authentication by default, or enforce IP allowlists and enable `STATS_SANITIZE_IDS=true` when auth is not set. Prefer failing startup if neither token nor allowlist is configured.
- **Mitigation:** Block `/stats` at the edge or enable `STATS_ALLOWED_IPS` and `STATS_SANITIZE_IDS` until auth is enforced.
- **False positive notes:** If `STATS_AUTH_TOKEN` is always configured (or `/stats` is restricted at the edge), exposure is mitigated.

### 3) Webhook Connect accepts auth tokens via URL query parameters
- **Rule ID:** FASTAPI-AUTH-002
- **Severity:** Medium
- **Location:**
  - `src/webhook_connect/api.py:56-81` (WebSocket: `token` from query params)
  - `src/webhook_connect/api.py:268-299` (SSE: `token` query parameter)
  - `src/webhook_connect/api.py:407-442` (Long-polling: `token` query parameter)
- **Evidence:**
  - WebSocket: `token = websocket.query_params.get("token", "")` (`src/webhook_connect/api.py:76-80`)
  - SSE: `token: str = Query(None)` and `auth_token = token` (`src/webhook_connect/api.py:268-292`)
  - Long-poll: `token: str = Query(None)` and `auth_token = token` (`src/webhook_connect/api.py:407-435`)
- **Impact:** Tokens in URLs are commonly logged by proxies, load balancers, browser history, and observability tools, leading to credential leakage.
- **Fix:** Require `Authorization` header by default and gate query-param token acceptance behind an explicit config flag (disabled by default). If query tokens must remain, use short-lived, scope-limited tokens and avoid logging URLs.
- **Mitigation:** Scrub query strings in access logs and edge proxies; prefer header-based auth for all clients.
- **False positive notes:** If clients never use `?token=...` and URL logging is fully scrubbed, leakage risk is reduced, but the code path still permits it.

---

## Summary of Findings
- **High:** 1
- **Medium:** 2
- **Low:** 0

---

If you want, I can implement fixes one finding at a time (starting with requiring admin/stats auth by default).
