"""
Unit tests for Webhook Connect Admin API.

Tests for admin endpoints including channel management, stats, and token rotation.
"""

import pytest
import os
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta

from fastapi import FastAPI
from httpx import AsyncClient, ASGITransport

from src.webhook_connect.admin_api import router, set_channel_manager, ADMIN_TOKEN
from src.webhook_connect.models import (
    ChannelConfig,
    ConnectorConnection,
    ConnectionProtocol,
    ChannelStats,
    WebhookMessage,
)


class MockChannelManager:
    """Mock channel manager for admin API testing."""

    def __init__(self):
        self.channels = {}
        self.connections = {}
        self.channel_connections = {}
        self.buffer = MockBuffer()
        self._token_rotation_result = None

    def list_channels(self):
        return list(self.channels.keys())

    def get_channel(self, name: str):
        return self.channels.get(name)

    def get_channel_connections(self, channel: str):
        conn_ids = self.channel_connections.get(channel, [])
        return [self.connections[c] for c in conn_ids if c in self.connections]

    def get_connection(self, connection_id: str):
        return self.connections.get(connection_id)

    async def remove_connection(self, connection_id: str):
        conn = self.connections.pop(connection_id, None)
        if conn:
            channel = conn.channel
            if channel in self.channel_connections:
                self.channel_connections[channel] = [
                    c for c in self.channel_connections[channel] if c != connection_id
                ]

    async def rotate_token(self, channel: str, grace_period: timedelta):
        if channel not in self.channels:
            return None
        return self._token_rotation_result or f"new_token_{channel}"

    async def get_channel_stats(self, channel: str):
        if channel not in self.channels:
            return None
        return ChannelStats(
            channel=channel,
            messages_queued=100,
            messages_in_flight=10,
            messages_delivered=500,
            messages_expired=5,
            messages_dead_lettered=2,
            connected_clients=len(self.channel_connections.get(channel, [])),
        )

    async def health_check(self):
        return {
            "buffer": True,
            "channels_count": len(self.channels),
            "connections_count": len(self.connections),
        }

    def get_all_stats(self):
        result = {}
        for name, config in self.channels.items():
            result[name] = {
                "webhook_id": config.webhook_id,
                "connected_clients": len(self.channel_connections.get(name, [])),
                "max_connections": config.max_connections,
                "ttl_seconds": int(config.ttl.total_seconds()),
            }
        return result


class MockBuffer:
    """Mock buffer for testing."""

    def __init__(self):
        self.dead_letters = []

    async def get_dead_letters(self, channel: str, limit: int = 100):
        return self.dead_letters[:limit]


@pytest.fixture
def mock_channel_manager():
    """Create mock channel manager with test data."""
    manager = MockChannelManager()

    # Add test channels
    manager.channels["channel-1"] = ChannelConfig(
        name="channel-1",
        webhook_id="webhook-1",
        channel_token="token-1",
        max_connections=10,
        created_at=datetime(2024, 1, 1, 12, 0, 0),
    )

    manager.channels["channel-2"] = ChannelConfig(
        name="channel-2",
        webhook_id="webhook-2",
        channel_token="token-2",
        max_connections=5,
        created_at=datetime(2024, 1, 2, 12, 0, 0),
    )

    # Add a connection to channel-1
    conn = ConnectorConnection(
        connection_id="conn-1",
        connector_id="connector-1",
        channel="channel-1",
        protocol=ConnectionProtocol.WEBSOCKET,
    )
    manager.connections["conn-1"] = conn
    manager.channel_connections["channel-1"] = ["conn-1"]

    return manager


@pytest.fixture
def app(mock_channel_manager):
    """Create test FastAPI app with admin router."""
    test_app = FastAPI()
    test_app.include_router(router)
    set_channel_manager(mock_channel_manager)

    yield test_app

    set_channel_manager(None)


class TestHealthEndpoint:
    """Tests for health check endpoint (no auth required)."""

    @pytest.mark.asyncio
    async def test_health_check_success(self, app):
        """Test health check returns status."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.get("/admin/webhook-connect/health")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "healthy"
            assert data["buffer"] is True
            assert data["channels_count"] == 2
            assert "timestamp" in data

    @pytest.mark.asyncio
    async def test_health_check_unhealthy(self, app, mock_channel_manager):
        """Test health check shows unhealthy when buffer is down."""
        # Override health check to return unhealthy
        async def unhealthy_check():
            return {"buffer": False, "channels_count": 2, "connections_count": 0}

        mock_channel_manager.health_check = unhealthy_check

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.get("/admin/webhook-connect/health")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "unhealthy"


class TestAuthenticationRequired:
    """Tests for endpoints requiring admin authentication."""

    @pytest.mark.asyncio
    async def test_list_channels_no_token_configured(self, app, monkeypatch):
        """Test endpoints fail when no admin token is configured."""
        # Patch ADMIN_TOKEN to empty
        import src.webhook_connect.admin_api as admin_api
        original_token = admin_api.ADMIN_TOKEN
        admin_api.ADMIN_TOKEN = ""

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.get("/admin/webhook-connect/channels")
                assert response.status_code == 403
                assert "Admin API disabled" in response.json()["detail"]
        finally:
            admin_api.ADMIN_TOKEN = original_token

    @pytest.mark.asyncio
    async def test_list_channels_missing_auth_header(self, app, monkeypatch):
        """Test endpoints fail without authorization header."""
        import src.webhook_connect.admin_api as admin_api
        original_token = admin_api.ADMIN_TOKEN
        admin_api.ADMIN_TOKEN = "admin-secret"

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.get("/admin/webhook-connect/channels")
                assert response.status_code == 401
                assert "Missing authorization header" in response.json()["detail"]
        finally:
            admin_api.ADMIN_TOKEN = original_token

    @pytest.mark.asyncio
    async def test_list_channels_invalid_token(self, app, monkeypatch):
        """Test endpoints fail with invalid token."""
        import src.webhook_connect.admin_api as admin_api
        original_token = admin_api.ADMIN_TOKEN
        admin_api.ADMIN_TOKEN = "admin-secret"

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.get(
                    "/admin/webhook-connect/channels",
                    headers={"Authorization": "Bearer wrong-token"},
                )
                assert response.status_code == 401
                assert "Invalid admin token" in response.json()["detail"]
        finally:
            admin_api.ADMIN_TOKEN = original_token


class TestListChannels:
    """Tests for channel listing endpoint."""

    @pytest.mark.asyncio
    async def test_list_channels_success(self, app, monkeypatch):
        """Test listing all channels."""
        import src.webhook_connect.admin_api as admin_api
        original_token = admin_api.ADMIN_TOKEN
        admin_api.ADMIN_TOKEN = "admin-secret"

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.get(
                    "/admin/webhook-connect/channels",
                    headers={"Authorization": "Bearer admin-secret"},
                )
                assert response.status_code == 200
                data = response.json()
                assert len(data) == 2

                # Check channel-1
                ch1 = next(c for c in data if c["name"] == "channel-1")
                assert ch1["webhook_id"] == "webhook-1"
                assert ch1["max_connections"] == 10
                assert ch1["connected_clients"] == 1
        finally:
            admin_api.ADMIN_TOKEN = original_token


class TestGetChannelDetails:
    """Tests for channel details endpoint."""

    @pytest.mark.asyncio
    async def test_get_channel_details_success(self, app, monkeypatch):
        """Test getting channel details."""
        import src.webhook_connect.admin_api as admin_api
        original_token = admin_api.ADMIN_TOKEN
        admin_api.ADMIN_TOKEN = "admin-secret"

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.get(
                    "/admin/webhook-connect/channels/channel-1",
                    headers={"Authorization": "Bearer admin-secret"},
                )
                assert response.status_code == 200
                data = response.json()
                assert data["name"] == "channel-1"
                assert data["webhook_id"] == "webhook-1"
                assert "config" in data
                assert "stats" in data
                assert "connected_clients" in data
        finally:
            admin_api.ADMIN_TOKEN = original_token

    @pytest.mark.asyncio
    async def test_get_channel_details_not_found(self, app, monkeypatch):
        """Test getting details for non-existent channel."""
        import src.webhook_connect.admin_api as admin_api
        original_token = admin_api.ADMIN_TOKEN
        admin_api.ADMIN_TOKEN = "admin-secret"

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.get(
                    "/admin/webhook-connect/channels/nonexistent",
                    headers={"Authorization": "Bearer admin-secret"},
                )
                assert response.status_code == 404
                assert "Channel not found" in response.json()["detail"]
        finally:
            admin_api.ADMIN_TOKEN = original_token


class TestRotateToken:
    """Tests for token rotation endpoint."""

    @pytest.mark.asyncio
    async def test_rotate_token_success(self, app, monkeypatch):
        """Test successful token rotation."""
        import src.webhook_connect.admin_api as admin_api
        original_token = admin_api.ADMIN_TOKEN
        admin_api.ADMIN_TOKEN = "admin-secret"

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.post(
                    "/admin/webhook-connect/channels/channel-1/rotate-token",
                    headers={"Authorization": "Bearer admin-secret"},
                    json={"grace_period_seconds": 1800},
                )
                assert response.status_code == 200
                data = response.json()
                assert data["channel"] == "channel-1"
                assert "new_token" in data
                assert "old_token_expires_at" in data
                assert "grace period" in data["message"].lower()
        finally:
            admin_api.ADMIN_TOKEN = original_token

    @pytest.mark.asyncio
    async def test_rotate_token_channel_not_found(self, app, monkeypatch):
        """Test token rotation for non-existent channel."""
        import src.webhook_connect.admin_api as admin_api
        original_token = admin_api.ADMIN_TOKEN
        admin_api.ADMIN_TOKEN = "admin-secret"

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.post(
                    "/admin/webhook-connect/channels/nonexistent/rotate-token",
                    headers={"Authorization": "Bearer admin-secret"},
                    json={"grace_period_seconds": 3600},
                )
                assert response.status_code == 404
        finally:
            admin_api.ADMIN_TOKEN = original_token


class TestDisconnectConnection:
    """Tests for connection disconnect endpoint."""

    @pytest.mark.asyncio
    async def test_disconnect_success(self, app, mock_channel_manager, monkeypatch):
        """Test disconnecting a connection."""
        import src.webhook_connect.admin_api as admin_api
        original_token = admin_api.ADMIN_TOKEN
        admin_api.ADMIN_TOKEN = "admin-secret"

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.delete(
                    "/admin/webhook-connect/channels/channel-1/connections/conn-1",
                    headers={"Authorization": "Bearer admin-secret"},
                )
                assert response.status_code == 200
                data = response.json()
                assert data["status"] == "disconnected"
                assert data["connection_id"] == "conn-1"

                # Verify connection was removed
                assert "conn-1" not in mock_channel_manager.connections
        finally:
            admin_api.ADMIN_TOKEN = original_token

    @pytest.mark.asyncio
    async def test_disconnect_connection_not_found(self, app, monkeypatch):
        """Test disconnecting non-existent connection."""
        import src.webhook_connect.admin_api as admin_api
        original_token = admin_api.ADMIN_TOKEN
        admin_api.ADMIN_TOKEN = "admin-secret"

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.delete(
                    "/admin/webhook-connect/channels/channel-1/connections/nonexistent",
                    headers={"Authorization": "Bearer admin-secret"},
                )
                assert response.status_code == 404
                assert "Connection not found" in response.json()["detail"]
        finally:
            admin_api.ADMIN_TOKEN = original_token

    @pytest.mark.asyncio
    async def test_disconnect_wrong_channel(self, app, monkeypatch):
        """Test disconnecting connection from wrong channel."""
        import src.webhook_connect.admin_api as admin_api
        original_token = admin_api.ADMIN_TOKEN
        admin_api.ADMIN_TOKEN = "admin-secret"

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                # conn-1 belongs to channel-1, not channel-2
                response = await ac.delete(
                    "/admin/webhook-connect/channels/channel-2/connections/conn-1",
                    headers={"Authorization": "Bearer admin-secret"},
                )
                assert response.status_code == 400
                assert "not on this channel" in response.json()["detail"]
        finally:
            admin_api.ADMIN_TOKEN = original_token


class TestChannelStats:
    """Tests for channel statistics endpoint."""

    @pytest.mark.asyncio
    async def test_get_channel_stats_success(self, app, monkeypatch):
        """Test getting channel statistics."""
        import src.webhook_connect.admin_api as admin_api
        original_token = admin_api.ADMIN_TOKEN
        admin_api.ADMIN_TOKEN = "admin-secret"

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.get(
                    "/admin/webhook-connect/channels/channel-1/stats",
                    headers={"Authorization": "Bearer admin-secret"},
                )
                assert response.status_code == 200
                data = response.json()
                assert data["channel"] == "channel-1"
                assert data["messages_queued"] == 100
                assert data["messages_delivered"] == 500
        finally:
            admin_api.ADMIN_TOKEN = original_token

    @pytest.mark.asyncio
    async def test_get_channel_stats_not_found(self, app, monkeypatch):
        """Test getting stats for non-existent channel."""
        import src.webhook_connect.admin_api as admin_api
        original_token = admin_api.ADMIN_TOKEN
        admin_api.ADMIN_TOKEN = "admin-secret"

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.get(
                    "/admin/webhook-connect/channels/nonexistent/stats",
                    headers={"Authorization": "Bearer admin-secret"},
                )
                assert response.status_code == 404
        finally:
            admin_api.ADMIN_TOKEN = original_token


class TestDeadLetters:
    """Tests for dead letter queue endpoint."""

    @pytest.mark.asyncio
    async def test_get_dead_letters_success(self, app, mock_channel_manager, monkeypatch):
        """Test getting dead letters."""
        import src.webhook_connect.admin_api as admin_api
        original_token = admin_api.ADMIN_TOKEN
        admin_api.ADMIN_TOKEN = "admin-secret"

        # Add some dead letters
        msg = WebhookMessage(
            channel="channel-1",
            webhook_id="webhook-1",
            payload={"test": "data"},
        )
        mock_channel_manager.buffer.dead_letters = [msg]

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.get(
                    "/admin/webhook-connect/channels/channel-1/dead-letters",
                    headers={"Authorization": "Bearer admin-secret"},
                )
                assert response.status_code == 200
                data = response.json()
                assert data["channel"] == "channel-1"
                assert data["count"] == 1
                assert len(data["messages"]) == 1
        finally:
            admin_api.ADMIN_TOKEN = original_token

    @pytest.mark.asyncio
    async def test_get_dead_letters_channel_not_found(self, app, monkeypatch):
        """Test getting dead letters for non-existent channel."""
        import src.webhook_connect.admin_api as admin_api
        original_token = admin_api.ADMIN_TOKEN
        admin_api.ADMIN_TOKEN = "admin-secret"

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.get(
                    "/admin/webhook-connect/channels/nonexistent/dead-letters",
                    headers={"Authorization": "Bearer admin-secret"},
                )
                assert response.status_code == 404
        finally:
            admin_api.ADMIN_TOKEN = original_token


class TestOverview:
    """Tests for overview endpoint."""

    @pytest.mark.asyncio
    async def test_get_overview_success(self, app, monkeypatch):
        """Test getting system overview."""
        import src.webhook_connect.admin_api as admin_api
        original_token = admin_api.ADMIN_TOKEN
        admin_api.ADMIN_TOKEN = "admin-secret"

        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.get(
                    "/admin/webhook-connect/overview",
                    headers={"Authorization": "Bearer admin-secret"},
                )
                assert response.status_code == 200
                data = response.json()
                assert "timestamp" in data
                assert "health" in data
                assert data["total_channels"] == 2
                assert data["total_connections"] == 1
                assert "channels" in data
        finally:
            admin_api.ADMIN_TOKEN = original_token


class TestChannelManagerNotInitialized:
    """Tests for when channel manager is not initialized."""

    @pytest.mark.asyncio
    async def test_health_returns_503(self):
        """Test health endpoint returns 503 when not initialized."""
        test_app = FastAPI()
        test_app.include_router(router)
        set_channel_manager(None)

        transport = ASGITransport(app=test_app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.get("/admin/webhook-connect/health")
            assert response.status_code == 503
            assert "not initialized" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_channels_returns_503(self, monkeypatch):
        """Test channels endpoint returns 503 when not initialized."""
        import src.webhook_connect.admin_api as admin_api
        original_token = admin_api.ADMIN_TOKEN
        admin_api.ADMIN_TOKEN = "admin-secret"

        test_app = FastAPI()
        test_app.include_router(router)
        set_channel_manager(None)

        try:
            transport = ASGITransport(app=test_app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.get(
                    "/admin/webhook-connect/channels",
                    headers={"Authorization": "Bearer admin-secret"},
                )
                assert response.status_code == 503
        finally:
            admin_api.ADMIN_TOKEN = original_token
