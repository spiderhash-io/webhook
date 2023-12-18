# tests/test_auth_endpoints.py
import pytest
from httpx import AsyncClient
from src.main import app

host = "test"
test_url = f"http://{ host }"


@pytest.mark.asyncio
async def test_app_response():
    async with AsyncClient(app=app, base_url=test_url) as ac:

        # test if app is running
        response = await ac.get("/")
        assert response.status_code == 200
        assert response.json() == {"message": "200 OK"}

        # test if app is running
        response = await ac.get("/stats")
        assert response.status_code == 200
