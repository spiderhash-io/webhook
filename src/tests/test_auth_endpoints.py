# tests/test_auth_endpoints.py
import pytest
import redis.asyncio as redis
from httpx import AsyncClient, ASGITransport
from src.main import app

host = "test"
test_url = f"http://{ host }"


def _check_redis_available():
    """Check if Redis is available for testing."""
    try:
        import redis.asyncio as redis
        import asyncio
        import os
        
        redis_host = os.getenv('REDIS_HOST', 'localhost')
        redis_port = int(os.getenv('REDIS_PORT', '6379'))
        
        # Try to connect synchronously (for skip check)
        import redis as sync_redis
        r = sync_redis.Redis(host=redis_host, port=redis_port, socket_connect_timeout=1)
        r.ping()
        r.close()
        return True
    except Exception:
        return False


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.skipif(not _check_redis_available(), reason="Redis not available")
async def test_app_response():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=test_url) as ac:

        # test if app is running
        response = await ac.get("/")
        assert response.status_code == 200
        assert response.json() == {"message": "200 OK"}

        # test stats endpoint is reachable; security config may change status code
        response = await ac.get("/stats")
        assert response.status_code in [200, 401, 403, 429]
