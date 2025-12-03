import pytest
from httpx import AsyncClient, ASGITransport

from src.main import app


host = "test"
base_url = f"http://{host}"


@pytest.mark.asyncio
async def test_stats_requires_token_when_configured(monkeypatch):
    """Ensure STATS_AUTH_TOKEN is enforced when configured."""
    # Configure token auth and disable IP whitelist to isolate behavior
    monkeypatch.setenv("STATS_AUTH_TOKEN", "secret-token")
    monkeypatch.delenv("STATS_ALLOWED_IPS", raising=False)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=base_url) as ac:
        # No auth header -> authentication required
        response = await ac.get("/stats")
        assert response.status_code == 401

        # Wrong token -> unauthorized
        response = await ac.get(
            "/stats", headers={"Authorization": "Bearer wrong-token"}
        )
        assert response.status_code == 401

        # Correct token as Bearer
        response = await ac.get(
            "/stats", headers={"Authorization": "Bearer secret-token"}
        )
        assert response.status_code == 200

        # Correct token without Bearer prefix is also accepted
        response = await ac.get(
            "/stats", headers={"Authorization": "secret-token"}
        )
        assert response.status_code == 200


@pytest.mark.asyncio
async def test_stats_ip_whitelist_enforced(monkeypatch):
    """Ensure STATS_ALLOWED_IPS restricts access based on client IP."""
    # Remove token auth so we only exercise IP whitelist behavior
    monkeypatch.delenv("STATS_AUTH_TOKEN", raising=False)
    monkeypatch.setenv("STATS_ALLOWED_IPS", "1.2.3.4")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=base_url) as ac:
        # Request from non-allowed IP via X-Forwarded-For -> forbidden
        response = await ac.get(
            "/stats", headers={"x-forwarded-for": "5.6.7.8"}
        )
        assert response.status_code == 403

        # Request from whitelisted IP -> allowed (or possibly rate limited)
        response = await ac.get(
            "/stats", headers={"x-forwarded-for": "1.2.3.4"}
        )
        assert response.status_code in (200, 429)


@pytest.mark.asyncio
async def test_stats_rate_limit_enforced(monkeypatch):
    """Ensure STATS_RATE_LIMIT applies per-client rate limiting."""
    # Disable auth and IP whitelist so we only test rate limiting
    monkeypatch.delenv("STATS_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("STATS_ALLOWED_IPS", raising=False)
    monkeypatch.setenv("STATS_RATE_LIMIT", "2")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=base_url) as ac:
        status_codes = []
        # Use a fixed client IP via X-Forwarded-For so all requests share the same key
        for _ in range(5):
            response = await ac.get(
                "/stats", headers={"x-forwarded-for": "9.9.9.9"}
            )
            status_codes.append(response.status_code)

        # At least one request should be rate limited
        assert any(code == 429 for code in status_codes)


