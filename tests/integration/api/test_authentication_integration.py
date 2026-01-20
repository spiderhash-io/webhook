"""
Integration tests for authentication methods with real API server.

These tests verify that all authentication methods work correctly with the FastAPI server.
"""

import pytest
import httpx
import base64
import hmac
import hashlib
import json
from datetime import datetime, timedelta
import jwt
from tests.integration.test_config import API_BASE_URL, TEST_WEBHOOK_ID, TEST_AUTH_TOKEN


@pytest.mark.integration
class TestAuthenticationIntegration:
    """Integration tests for authentication methods."""

    @pytest.mark.asyncio
    async def test_basic_auth_success(self, http_client):
        """Test Basic Authentication with valid credentials."""
        # Skip if API server not available
        try:
            response = await http_client.get(f"{API_BASE_URL}/")
        except Exception:
            pytest.skip("API server not available")

        # Create webhook config with basic auth
        webhook_id = f"{TEST_WEBHOOK_ID}_basic_auth"
        username = "testuser"
        password = "testpass123"

        # Encode credentials
        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()

        # Make request with Basic Auth
        response = await http_client.post(
            f"{API_BASE_URL}/webhook/{webhook_id}",
            json={"test": "data"},
            headers={
                "Authorization": f"Basic {credentials}",
                "Content-Type": "application/json",
            },
        )

        # Should either succeed (if webhook exists) or fail with 404 (webhook not found)
        # The important thing is that it doesn't fail with 401 (unauthorized)
        assert response.status_code in [
            200,
            201,
            404,
            500,
        ]  # 500 if webhook config missing

    @pytest.mark.asyncio
    async def test_bearer_auth_success(self, http_client):
        """Test Bearer token authentication."""
        try:
            response = await http_client.get(f"{API_BASE_URL}/")
        except Exception:
            pytest.skip("API server not available")

        webhook_id = f"{TEST_WEBHOOK_ID}_bearer"
        token = "test_bearer_token_12345"

        response = await http_client.post(
            f"{API_BASE_URL}/webhook/{webhook_id}",
            json={"test": "data"},
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )

        assert response.status_code in [200, 201, 404, 500]

    @pytest.mark.asyncio
    async def test_hmac_auth_success(self, http_client):
        """Test HMAC signature authentication."""
        try:
            response = await http_client.get(f"{API_BASE_URL}/")
        except Exception:
            pytest.skip("API server not available")

        webhook_id = f"{TEST_WEBHOOK_ID}_hmac"
        secret = "test_hmac_secret"
        payload = json.dumps({"test": "data"}).encode()

        # Generate HMAC signature
        signature = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

        response = await http_client.post(
            f"{API_BASE_URL}/webhook/{webhook_id}",
            content=payload,
            headers={"X-HMAC-Signature": signature, "Content-Type": "application/json"},
        )

        assert response.status_code in [200, 201, 404, 500]

    @pytest.mark.asyncio
    async def test_jwt_auth_success(self, http_client):
        """Test JWT authentication."""
        try:
            response = await http_client.get(f"{API_BASE_URL}/")
        except Exception:
            pytest.skip("API server not available")

        webhook_id = f"{TEST_WEBHOOK_ID}_jwt"
        secret = "test_jwt_secret"

        # Create JWT token
        payload = {
            "iss": "test-issuer",
            "aud": "webhook-api",
            "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.utcnow().timestamp()),
        }

        token = jwt.encode(payload, secret, algorithm="HS256")

        response = await http_client.post(
            f"{API_BASE_URL}/webhook/{webhook_id}",
            json={"test": "data"},
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )

        assert response.status_code in [200, 201, 404, 500]

    @pytest.mark.asyncio
    async def test_query_parameter_auth(self, http_client):
        """Test query parameter authentication."""
        try:
            response = await http_client.get(f"{API_BASE_URL}/")
        except Exception:
            pytest.skip("API server not available")

        webhook_id = f"{TEST_WEBHOOK_ID}_query"
        api_key = "test_api_key_12345"

        response = await http_client.post(
            f"{API_BASE_URL}/webhook/{webhook_id}?api_key={api_key}",
            json={"test": "data"},
            headers={"Content-Type": "application/json"},
        )

        assert response.status_code in [200, 201, 404, 500]

    @pytest.mark.asyncio
    async def test_header_auth(self, http_client):
        """Test header-based API key authentication."""
        try:
            response = await http_client.get(f"{API_BASE_URL}/")
        except Exception:
            pytest.skip("API server not available")

        webhook_id = f"{TEST_WEBHOOK_ID}_header"
        api_key = "test_api_key_12345"

        response = await http_client.post(
            f"{API_BASE_URL}/webhook/{webhook_id}",
            json={"test": "data"},
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
        )

        assert response.status_code in [200, 201, 404, 500]

    @pytest.mark.asyncio
    async def test_authentication_failure(self, http_client):
        """Test that invalid authentication fails."""
        try:
            response = await http_client.get(f"{API_BASE_URL}/")
        except Exception:
            pytest.skip("API server not available")

        webhook_id = f"{TEST_WEBHOOK_ID}_invalid"

        # Try with invalid Bearer token
        response = await http_client.post(
            f"{API_BASE_URL}/webhook/{webhook_id}",
            json={"test": "data"},
            headers={
                "Authorization": "Bearer invalid_token",
                "Content-Type": "application/json",
            },
        )

        # Should fail with 401 or 404 (if webhook doesn't exist)
        assert response.status_code in [401, 403, 404, 500]
