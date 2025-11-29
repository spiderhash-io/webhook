"""
Integration tests for webhook API endpoints.

These tests make real HTTP calls to a running FastAPI server.
"""

import pytest
import httpx
from tests.integration.utils import make_authenticated_request


@pytest.mark.integration
class TestWebhookEndpoints:
    """Integration tests for webhook API endpoints."""
    
    @pytest.mark.asyncio
    async def test_root_endpoint(self, http_client: httpx.AsyncClient):
        """Test the root endpoint."""
        response = await http_client.get("/")
        assert response.status_code == 200
        assert response.json() == {"message": "200 OK"}
    
    @pytest.mark.asyncio
    async def test_stats_endpoint(self, http_client: httpx.AsyncClient):
        """Test the stats endpoint."""
        response = await http_client.get("/stats")
        assert response.status_code == 200
        stats = response.json()
        assert isinstance(stats, dict)
    
    @pytest.mark.asyncio
    async def test_webhook_with_authentication(
        self,
        http_client: httpx.AsyncClient,
        test_webhook_id: str,
        test_auth_token: str
    ):
        """Test webhook endpoint with valid authentication."""
        payload = {"test": "data", "integration": True}
        
        response = await make_authenticated_request(
            http_client,
            "POST",
            f"/webhook/{test_webhook_id}",
            auth_token=test_auth_token,
            json=payload
        )
        
        # Should succeed if webhook is configured, or 404 if not
        assert response.status_code in [200, 404]
        if response.status_code == 200:
            assert response.json() == {"message": "200 OK"}
    
    @pytest.mark.asyncio
    async def test_webhook_without_authentication(
        self,
        http_client: httpx.AsyncClient,
        test_webhook_id: str
    ):
        """Test webhook endpoint without authentication."""
        payload = {"test": "data"}
        
        response = await http_client.post(
            f"/webhook/{test_webhook_id}",
            json=payload
        )
        
        # Should return 401 Unauthorized if auth is required
        assert response.status_code in [401, 404]
        if response.status_code == 401:
            assert "Unauthorized" in response.json().get("detail", "")
    
    @pytest.mark.asyncio
    async def test_webhook_with_invalid_auth(
        self,
        http_client: httpx.AsyncClient,
        test_webhook_id: str
    ):
        """Test webhook endpoint with invalid authentication."""
        payload = {"test": "data"}
        
        response = await make_authenticated_request(
            http_client,
            "POST",
            f"/webhook/{test_webhook_id}",
            auth_token="invalid_token",
            json=payload
        )
        
        # Should return 401 Unauthorized
        assert response.status_code in [401, 404]
        if response.status_code == 401:
            assert "Unauthorized" in response.json().get("detail", "")
    
    @pytest.mark.asyncio
    async def test_webhook_nonexistent(
        self,
        http_client: httpx.AsyncClient,
        test_auth_token: str
    ):
        """Test webhook endpoint with non-existent webhook ID."""
        payload = {"test": "data"}
        
        response = await make_authenticated_request(
            http_client,
            "POST",
            "/webhook/nonexistent_webhook_12345",
            auth_token=test_auth_token,
            json=payload
        )
        
        # Should return 404 Not Found
        assert response.status_code == 404
        assert "not found" in response.json().get("detail", "").lower()
    
    @pytest.mark.asyncio
    async def test_webhook_invalid_json(
        self,
        http_client: httpx.AsyncClient,
        test_webhook_id: str,
        test_auth_token: str
    ):
        """Test webhook endpoint with invalid JSON."""
        response = await make_authenticated_request(
            http_client,
            "POST",
            f"/webhook/{test_webhook_id}",
            auth_token=test_auth_token,
            content="invalid json{",
            headers={"Content-Type": "application/json"}
        )
        
        # Should return 400 Bad Request or 422 Unprocessable Entity
        assert response.status_code in [400, 422]

