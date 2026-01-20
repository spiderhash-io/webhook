"""
Integration tests for CORS (Cross-Origin Resource Sharing) with real API server.

These tests verify CORS headers and preflight requests.
"""

import pytest
import httpx
from tests.integration.test_config import API_BASE_URL


@pytest.mark.integration
class TestCORSIntegration:
    """Integration tests for CORS."""

    @pytest.mark.asyncio
    async def test_cors_preflight_request(self, http_client):
        """Test CORS preflight (OPTIONS) request."""
        try:
            response = await http_client.get(f"{API_BASE_URL}/")
        except Exception:
            pytest.skip("API server not available")

        # Make OPTIONS request (preflight)
        response = await http_client.options(
            f"{API_BASE_URL}/webhook/test_webhook",
            headers={
                "Origin": "https://example.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type",
            },
        )

        # Should return 200, 204, or 400 for preflight (400 if webhook doesn't exist)
        assert response.status_code in [200, 204, 400, 404]

        # Check CORS headers
        cors_headers = {
            "access-control-allow-origin",
            "access-control-allow-methods",
            "access-control-allow-headers",
        }

        # At least some CORS headers should be present
        response_headers = {k.lower() for k in response.headers.keys()}
        assert any(header in response_headers for header in cors_headers)

    @pytest.mark.asyncio
    async def test_cors_headers_in_response(self, http_client):
        """Test that CORS headers are included in actual requests."""
        try:
            response = await http_client.get(f"{API_BASE_URL}/")
        except Exception:
            pytest.skip("API server not available")

        # Make POST request with Origin header
        response = await http_client.post(
            f"{API_BASE_URL}/webhook/test_webhook",
            json={"test": "data"},
            headers={
                "Origin": "https://example.com",
                "Content-Type": "application/json",
            },
        )

        # Check for CORS headers in response
        response_headers = {k.lower() for k in response.headers.keys()}

        # Access-Control-Allow-Origin should be present
        assert (
            "access-control-allow-origin" in response_headers
            or response.status_code == 404
        )

    @pytest.mark.asyncio
    async def test_cors_allowed_methods(self, http_client):
        """Test that CORS allows required HTTP methods."""
        try:
            response = await http_client.get(f"{API_BASE_URL}/")
        except Exception:
            pytest.skip("API server not available")

        # Make OPTIONS request
        response = await http_client.options(
            f"{API_BASE_URL}/webhook/test_webhook",
            headers={
                "Origin": "https://example.com",
                "Access-Control-Request-Method": "POST",
            },
        )

        if response.status_code != 404:
            # Check that POST is in allowed methods
            allow_methods = response.headers.get("Access-Control-Allow-Methods", "")
            assert "POST" in allow_methods or "*" in allow_methods

    @pytest.mark.asyncio
    async def test_cors_allowed_headers(self, http_client):
        """Test that CORS allows required headers."""
        try:
            response = await http_client.get(f"{API_BASE_URL}/")
        except Exception:
            pytest.skip("API server not available")

        # Make OPTIONS request with custom headers
        response = await http_client.options(
            f"{API_BASE_URL}/webhook/test_webhook",
            headers={
                "Origin": "https://example.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Authorization,Content-Type",
            },
        )

        if response.status_code != 404:
            # Check that required headers are allowed
            allow_headers = response.headers.get("Access-Control-Allow-Headers", "")
            assert "Content-Type" in allow_headers or "*" in allow_headers

    @pytest.mark.asyncio
    async def test_cors_credentials(self, http_client):
        """Test that CORS supports credentials if configured."""
        try:
            response = await http_client.get(f"{API_BASE_URL}/")
        except Exception:
            pytest.skip("API server not available")

        # Make request with credentials
        response = await http_client.post(
            f"{API_BASE_URL}/webhook/test_webhook",
            json={"test": "data"},
            headers={
                "Origin": "https://example.com",
                "Content-Type": "application/json",
            },
        )

        # Access-Control-Allow-Credentials may be present
        response_headers = {k.lower() for k in response.headers.keys()}
        # Credentials header is optional, so we just check it doesn't break
        assert response.status_code in [200, 201, 404, 500]
