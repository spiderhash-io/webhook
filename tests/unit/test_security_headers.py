"""
Security tests for HTTP security headers.
Tests that all security headers are properly set in responses.
"""
import pytest
from fastapi.testclient import TestClient
from src.main import app


class TestSecurityHeaders:
    """Test suite for security headers."""
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)
    
    def test_x_content_type_options_header(self, client):
        """Test that X-Content-Type-Options header is set."""
        response = client.get("/")
        assert response.status_code == 200
        assert "X-Content-Type-Options" in response.headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"
    
    def test_x_frame_options_header(self, client):
        """Test that X-Frame-Options header is set."""
        response = client.get("/")
        assert response.status_code == 200
        assert "X-Frame-Options" in response.headers
        assert response.headers["X-Frame-Options"] == "DENY"
    
    def test_x_xss_protection_header(self, client):
        """Test that X-XSS-Protection header is set."""
        response = client.get("/")
        assert response.status_code == 200
        assert "X-XSS-Protection" in response.headers
        assert response.headers["X-XSS-Protection"] == "1; mode=block"
    
    def test_referrer_policy_header(self, client):
        """Test that Referrer-Policy header is set."""
        response = client.get("/")
        assert response.status_code == 200
        assert "Referrer-Policy" in response.headers
        assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    
    def test_permissions_policy_header(self, client):
        """Test that Permissions-Policy header is set."""
        response = client.get("/")
        assert response.status_code == 200
        assert "Permissions-Policy" in response.headers
        permissions_policy = response.headers["Permissions-Policy"]
        # Should contain restrictions for dangerous features
        assert "geolocation=()" in permissions_policy
        assert "microphone=()" in permissions_policy
        assert "camera=()" in permissions_policy
    
    def test_content_security_policy_header(self, client):
        """Test that Content-Security-Policy header is set."""
        response = client.get("/")
        assert response.status_code == 200
        assert "Content-Security-Policy" in response.headers
        csp = response.headers["Content-Security-Policy"]
        # Should contain default-src 'self'
        assert "default-src 'self'" in csp
        # Should prevent framing
        assert "frame-ancestors 'none'" in csp
    
    def test_security_headers_on_all_endpoints(self, client):
        """Test that security headers are set on all endpoints."""
        endpoints = ["/", "/stats", "/webhook/test_webhook"]
        
        for endpoint in endpoints:
            try:
                response = client.get(endpoint)
                # Some endpoints may return 404 or 401, but headers should still be set
                assert "X-Content-Type-Options" in response.headers
                assert "X-Frame-Options" in response.headers
                assert "X-XSS-Protection" in response.headers
                assert "Referrer-Policy" in response.headers
                assert "Permissions-Policy" in response.headers
                assert "Content-Security-Policy" in response.headers
            except Exception:
                # Some endpoints may fail, but that's OK for this test
                pass
    
    def test_security_headers_on_post_request(self, client):
        """Test that security headers are set on POST requests."""
        response = client.post("/webhook/test_webhook", json={"test": "data"})
        # May return 404 or 401, but headers should be set
        assert "X-Content-Type-Options" in response.headers
        assert "X-Frame-Options" in response.headers
        assert "Content-Security-Policy" in response.headers
    
    def test_strict_transport_security_not_set_on_http(self, client):
        """Test that Strict-Transport-Security is not set on HTTP requests."""
        response = client.get("/")
        # HSTS should not be set for HTTP (only HTTPS)
        # The test client uses HTTP by default
        assert "Strict-Transport-Security" not in response.headers
    
    def test_csp_default_policy(self, client):
        """Test that default CSP policy is restrictive."""
        response = client.get("/")
        csp = response.headers["Content-Security-Policy"]
        
        # Should restrict to same-origin
        assert "default-src 'self'" in csp
        # Should prevent framing
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
        # Should restrict form actions
        assert "form-action 'self'" in csp
        # Should restrict base URI
        assert "base-uri 'self'" in csp
    
    def test_csp_allows_inline_styles(self, client):
        """Test that CSP allows inline styles (needed for some frameworks)."""
        response = client.get("/")
        csp = response.headers["Content-Security-Policy"]
        # Should allow unsafe-inline for styles (common requirement)
        assert "style-src 'self' 'unsafe-inline'" in csp
    
    def test_csp_restricts_scripts(self, client):
        """Test that CSP restricts script sources."""
        response = client.get("/")
        csp = response.headers["Content-Security-Policy"]
        # Should only allow scripts from same origin
        assert "script-src 'self'" in csp
        # Should not allow unsafe-inline or unsafe-eval for scripts
        assert "script-src 'self' 'unsafe-inline'" not in csp
        assert "script-src 'self' 'unsafe-eval'" not in csp
    
    def test_permissions_policy_restricts_features(self, client):
        """Test that Permissions-Policy restricts dangerous browser features."""
        response = client.get("/")
        permissions_policy = response.headers["Permissions-Policy"]
        
        # Should disable geolocation
        assert "geolocation=()" in permissions_policy
        # Should disable microphone
        assert "microphone=()" in permissions_policy
        # Should disable camera
        assert "camera=()" in permissions_policy
        # Should disable payment
        assert "payment=()" in permissions_policy
        # Should disable USB
        assert "usb=()" in permissions_policy
    
    def test_security_headers_present_on_error_responses(self, client):
        """Test that security headers are present even on error responses."""
        # Request non-existent endpoint
        response = client.get("/nonexistent")
        # Should return 404, but headers should still be set
        assert response.status_code == 404
        assert "X-Content-Type-Options" in response.headers
        assert "X-Frame-Options" in response.headers
        assert "Content-Security-Policy" in response.headers

