"""
Tests for CORS support.
"""

import pytest
import os
from unittest.mock import patch
from httpx import AsyncClient, ASGITransport
from src.main import app


@pytest.mark.asyncio
async def test_cors_headers():
    """Test that CORS headers are present in response when origin is whitelisted."""
    # Set CORS_ALLOWED_ORIGINS for this test
    with patch.dict(os.environ, {"CORS_ALLOWED_ORIGINS": "http://example.com"}):
        # Reimport to get fresh CORS config
        import importlib
        import src.main

        importlib.reload(src.main)

        transport = ASGITransport(app=src.main.app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            # Preflight request (OPTIONS)
            response = await ac.options(
                "/webhook/test_webhook",
                headers={
                    "Origin": "http://example.com",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "Content-Type, Authorization",
                },
            )

            assert response.status_code == 200
            # When origin is whitelisted, allow-origin reflects the origin
            assert (
                response.headers["access-control-allow-origin"] == "http://example.com"
            )
            assert "POST" in response.headers["access-control-allow-methods"]
            assert (
                "authorization"
                in response.headers["access-control-allow-headers"].lower()
            )


@pytest.mark.asyncio
async def test_cors_simple_request():
    """Test CORS headers on simple GET request when origin is whitelisted."""
    # Set CORS_ALLOWED_ORIGINS for this test
    with patch.dict(os.environ, {"CORS_ALLOWED_ORIGINS": "http://example.com"}):
        # Reimport to get fresh CORS config
        import importlib
        import src.main

        importlib.reload(src.main)

        transport = ASGITransport(app=src.main.app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.get("/", headers={"Origin": "http://example.com"})

            assert response.status_code == 200
            assert (
                response.headers["access-control-allow-origin"] == "http://example.com"
            )
