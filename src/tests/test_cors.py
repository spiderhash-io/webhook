"""
Tests for CORS support.
"""
import pytest
from httpx import AsyncClient, ASGITransport
from src.main import app


@pytest.mark.asyncio
async def test_cors_headers():
    """Test that CORS headers are present in response."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Preflight request (OPTIONS)
        response = await ac.options(
            "/webhook/test_webhook",
            headers={
                "Origin": "http://example.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type, Authorization"
            }
        )
        
        assert response.status_code == 200
        # When allow_credentials=True, allow-origin reflects the origin
        assert response.headers["access-control-allow-origin"] == "http://example.com"
        assert "POST" in response.headers["access-control-allow-methods"]
        assert "authorization" in response.headers["access-control-allow-headers"].lower()


@pytest.mark.asyncio
async def test_cors_simple_request():
    """Test CORS headers on simple GET request."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.get(
            "/",
            headers={"Origin": "http://example.com"}
        )
        
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] in ["*", "http://example.com"]
