import pytest
from httpx import AsyncClient, ASGITransport
from src.main import app

host = "test"
test_url = f"http://{ host }"

@pytest.mark.asyncio
async def test_webhook_print():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=test_url) as ac:
        payload = {"key": "value"}
        response = await ac.post("/webhook/print", json=payload)
        assert response.status_code == 200
        assert response.json() == {"message": "200 OK"}

@pytest.mark.asyncio
async def test_webhook_auth_failure():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=test_url) as ac:
        payload = {"key": "value"}
        # Missing Authorization header
        response = await ac.post("/webhook/abcde", json=payload)
        assert response.status_code == 401
        assert response.json() == {"detail": "Unauthorized"}

        # Wrong Authorization header
        response = await ac.post("/webhook/abcde", json=payload, headers={"Authorization": "wrong"})
        assert response.status_code == 401
        assert response.json() == {"detail": "Unauthorized"}

import os
import shutil
import asyncio

@pytest.mark.asyncio
async def test_webhook_save_to_disk():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=test_url) as ac:
        payload = {"key": "value"}
        
        # Ensure directory is clean before test
        if os.path.exists("webhooks"):
            shutil.rmtree("webhooks")
            
        # Correct Authorization header
        response = await ac.post("/webhook/abcde", json=payload, headers={"Authorization": "secret"})
        assert response.status_code == 200
        assert response.json() == {"message": "200 OK"}
        
        # Wait for async task to complete
        await asyncio.sleep(0.1)
        
        # Verify file exists
        assert os.path.exists("webhooks")
        files = os.listdir("webhooks")
        assert len(files) == 1
        assert files[0].endswith(".txt")
        
        # Cleanup
        shutil.rmtree("webhooks")
