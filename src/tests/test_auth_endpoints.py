# tests/test_auth_endpoints.py
import pytest
from httpx import AsyncClient, ASGITransport
from src.main import app

host = "test"
test_url = f"http://{ host }"


@pytest.mark.asyncio
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
