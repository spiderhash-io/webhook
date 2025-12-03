# Smee-Client (probot/smee-client) Test Coverage Comparison

## Analysis Summary

After reviewing smee-client's test suite (TypeScript tests in `test/` directory), I've identified several testing areas that smee-client covers which may be missing or could be enhanced in our codebase.

## Comparison with Our Existing Tests

Our codebase has extensive security testing (SSRF, header injection, authentication, etc.) and functional tests (webhookd patterns), but may be missing some connection/forwarding-specific tests that smee-client includes.

## Smee-Client Test Files Analyzed

1. **connection-error.test.ts** - Tests WebSocket connection error handling
2. **connection-timeout.test.ts** - Tests connection timeout scenarios
3. **create-channel.test.ts** - Tests channel creation (not applicable to our HTTP-based system)
4. **forward.test.ts** - Tests webhook forwarding functionality
5. **index.test.ts** - Tests main client initialization
6. **onerror.test.ts** - Tests error callback handling
7. **onmessage.test.ts** - Tests message handling (WebSocket-specific)
8. **onopen.test.ts** - Tests connection open handling (WebSocket-specific)
9. **query-forwarding.test.ts** - Tests query parameter forwarding from source to target

## Missing Test Coverage - Todo List

1. **HTTP Connection Timeout Handling**: Test that HTTP webhook forwarding properly handles connection timeouts when the target server is unreachable or slow, ensuring appropriate error messages are returned without exposing internal details.

2. **HTTP Connection Error Types**: Test different types of HTTP connection errors (DNS resolution failure, connection refused, network unreachable, SSL errors) and verify that each is handled gracefully with appropriate error messages.

3. **Query Parameter Forwarding**: Test that query parameters from incoming webhook requests can be optionally forwarded to the target HTTP endpoint, preserving important parameters like webhook IDs or tracking tokens.

4. **HTTP Forwarding Error Callbacks**: Test that errors during HTTP forwarding trigger appropriate error handling mechanisms and that failed forwarding attempts are logged correctly for monitoring.

5. **Connection Retry on Transient Errors**: Test that connection retries work correctly for transient HTTP errors (timeouts, connection refused) but not for permanent errors (404, 401), ensuring retry logic differentiates between retryable and non-retryable failures.

6. **HTTP Method Preservation**: Test that the original HTTP method (POST, PUT, PATCH) is correctly preserved when forwarding webhooks, and that unsupported methods are rejected with appropriate error messages.

7. **Target Server Response Handling**: Test that different HTTP response codes from target servers (200, 201, 400, 401, 500) are handled appropriately, with successful responses logged and error responses triggering retry logic when applicable.

8. **Concurrent Forwarding Requests**: Test that multiple simultaneous webhook forwarding requests to the same or different targets are handled correctly without connection pool exhaustion or race conditions.

9. **HTTP Forwarding with Custom Headers**: Test that custom headers configured in the webhook config are correctly merged with forwarded headers, and that header conflicts are resolved appropriately (custom headers override forwarded headers).

10. **Connection Pool Management**: Test that HTTP connection pools are properly managed when forwarding multiple webhooks, ensuring connections are reused efficiently and closed when no longer needed.

11. **Target URL Validation at Runtime**: Test that target URLs are validated not just at initialization but also checked for validity before each forwarding attempt, catching configuration changes or invalid URLs dynamically.

12. **HTTP Redirect Handling**: Test that HTTP redirects (301, 302, 307, 308) from target servers are handled correctly, either following redirects or rejecting them based on configuration, to prevent SSRF via redirect chains.

13. **Request Body Size Limits**: Test that large webhook payloads are handled correctly when forwarding, ensuring that body size limits are respected and appropriate errors are returned if payloads exceed limits.

14. **Content-Type Preservation**: Test that the original Content-Type header is preserved when forwarding webhooks, and that JSON payloads are correctly serialized and forwarded with the appropriate Content-Type header.

15. **HTTP Forwarding with Authentication**: Test that authentication credentials (Basic Auth, Bearer tokens) configured in the webhook config are correctly added to forwarded requests, and that authentication failures are handled gracefully.

16. **Network Partition Recovery**: Test that when network partitions occur during forwarding, the system correctly detects the failure and either retries or fails gracefully, without hanging or consuming resources indefinitely.

17. **Target Server Unavailability**: Test that when target servers are completely unavailable (DNS failure, firewall blocking), the system handles the error appropriately and doesn't retry indefinitely, respecting retry limits and backoff strategies.

18. **HTTP Forwarding Metrics**: Test that forwarding metrics (success rate, latency, error counts) are correctly tracked and can be queried, enabling monitoring of forwarding health and performance.

19. **Idempotency Key Forwarding**: Test that idempotency keys or request IDs from incoming webhooks can be optionally forwarded to target endpoints, enabling downstream systems to handle duplicate requests correctly.

20. **HTTP Forwarding with Proxy**: Test that HTTP forwarding works correctly when the system is behind a proxy, ensuring that proxy configuration is respected and that forwarded requests use the proxy when configured.

---

## Notes

- Smee-client is a WebSocket-based proxy, while our system is HTTP-based, so some tests (onopen, onmessage) are not directly applicable.
- Our system already has retry logic, but connection-specific retry tests may be missing.
- Query parameter forwarding is a feature we may want to add if not already present.
- Connection pool management is important for high-throughput scenarios.

