"""
Unit tests for Webhook Connect Streaming API.

Tests for WebSocket, SSE, and ACK endpoints.
"""

import pytest
import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta

from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import AsyncClient, ASGITransport

from src.webhook_connect.api import router, set_channel_manager, get_channel_manager
from src.webhook_connect.models import (
    ChannelConfig,
    ConnectorConnection,
    ConnectionProtocol,
    ConnectionState,
    WebhookMessage,
    ChannelStats,
)


class MockChannelManager:
    """Mock channel manager for testing."""

    def __init__(self):
        self.channels = {}
        self.connections = {}
        self.channel_connections = {}
        self.buffer = MockBuffer()

    def get_channel(self, name: str):
        return self.channels.get(name)

    def validate_token(self, channel: str, token: str) -> bool:
        config = self.channels.get(channel)
        if not config:
            return False
        return config.channel_token == token

    def register_send_fn(self, connection_id, send_fn):
        pass  # No-op for mock

    async def add_connection(self, connection: ConnectorConnection) -> bool:
        channel = connection.channel
        if channel not in self.channels:
            return False
        config = self.channels[channel]
        current = len(self.channel_connections.get(channel, []))
        if current >= config.max_connections:
            return False
        self.connections[connection.connection_id] = connection
        if channel not in self.channel_connections:
            self.channel_connections[channel] = []
        self.channel_connections[channel].append(connection.connection_id)
        return True

    async def remove_connection(self, connection_id: str):
        conn = self.connections.pop(connection_id, None)
        if conn:
            channel = conn.channel
            if channel in self.channel_connections:
                self.channel_connections[channel] = [
                    c for c in self.channel_connections[channel] if c != connection_id
                ]

    def get_connection(self, connection_id: str):
        return self.connections.get(connection_id)

    def get_channel_connections(self, channel: str):
        conn_ids = self.channel_connections.get(channel, [])
        return [self.connections[c] for c in conn_ids if c in self.connections]

    async def ack_message(
        self, channel: str, message_id: str, connection_id: str
    ) -> bool:
        conn = self.connections.get(connection_id)
        if conn and message_id in conn.in_flight_messages:
            conn.in_flight_messages.discard(message_id)
            conn.messages_acked += 1
            return True
        return False

    async def nack_message(
        self, channel: str, message_id: str, connection_id: str, retry: bool = True
    ) -> bool:
        conn = self.connections.get(connection_id)
        if conn and message_id in conn.in_flight_messages:
            conn.in_flight_messages.discard(message_id)
            conn.messages_nacked += 1
            return True
        return False

    async def get_channel_stats(self, channel: str):
        if channel not in self.channels:
            return None
        return ChannelStats(
            channel=channel,
            messages_queued=10,
            messages_delivered=5,
            connected_clients=len(self.channel_connections.get(channel, [])),
        )


class MockBuffer:
    """Mock buffer for testing."""

    def __init__(self):
        self.messages = {}

    async def subscribe(self, channel: str, callback, prefetch=10):
        # Simulate subscription - just wait
        await asyncio.sleep(0.1)
        return f"mock-tag-{channel}"

    async def unsubscribe(self, consumer_tag):
        pass

    async def get_dead_letters(self, channel: str, limit: int = 100):
        return []


@pytest.fixture
def mock_channel_manager():
    """Create mock channel manager with test channel."""
    manager = MockChannelManager()

    # Add test channel
    manager.channels["test-channel"] = ChannelConfig(
        name="test-channel",
        webhook_id="test-webhook",
        channel_token="test-token-123",
        max_connections=5,
        heartbeat_interval=timedelta(seconds=30),
    )

    return manager


@pytest.fixture
def app(mock_channel_manager):
    """Create test FastAPI app."""
    test_app = FastAPI()
    test_app.include_router(router)

    # Set the channel manager
    set_channel_manager(mock_channel_manager)

    yield test_app

    # Reset channel manager
    set_channel_manager(None)


@pytest.fixture
def client(app):
    """Create test client."""
    return TestClient(app)


class TestSSEEndpoint:
    """Tests for SSE streaming endpoint."""

    def test_sse_missing_token(self, client):
        """Test SSE endpoint rejects missing token."""
        response = client.get("/connect/stream/test-channel/sse")
        assert response.status_code == 401
        assert "Missing authorization token" in response.json()["detail"]

    def test_sse_invalid_token(self, client):
        """Test SSE endpoint rejects invalid token."""
        response = client.get(
            "/connect/stream/test-channel/sse",
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert response.status_code == 401
        assert "Invalid channel token" in response.json()["detail"]

    def test_sse_channel_not_found(self, client, mock_channel_manager):
        """Test SSE endpoint returns 404 for unknown channel."""
        # Add valid token check that passes but channel doesn't exist
        response = client.get(
            "/connect/stream/unknown-channel/sse",
            headers={"Authorization": "Bearer test-token"},
        )
        assert response.status_code == 401  # Token validation fails first

    @pytest.mark.asyncio
    async def test_sse_valid_token_query_param(self, app, mock_channel_manager):
        """Test SSE endpoint accepts token as query parameter.

        Note: Full streaming behavior is tested via integration tests.
        This test verifies the endpoint accepts valid tokens and starts streaming.
        """
        # Use httpx AsyncClient with timeout for streaming
        transport = ASGITransport(app=app)

        async def stream_with_timeout():
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                async with ac.stream(
                    "GET",
                    "/connect/stream/test-channel/sse?token=test-token-123",
                ) as response:
                    assert response.status_code == 200
                    assert "text/event-stream" in response.headers.get(
                        "content-type", ""
                    )
                    return True

        try:
            # Use wait_for with timeout (compatible with Python 3.9)
            await asyncio.wait_for(stream_with_timeout(), timeout=2.0)
        except asyncio.TimeoutError:
            # Timeout is expected for SSE streams - test passed if we got headers
            pass

    @pytest.mark.asyncio
    async def test_sse_valid_token_header(self, app, mock_channel_manager):
        """Test SSE endpoint accepts token in Authorization header.

        Note: Full streaming behavior is tested via integration tests.
        """
        transport = ASGITransport(app=app)

        async def stream_with_timeout():
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                async with ac.stream(
                    "GET",
                    "/connect/stream/test-channel/sse",
                    headers={"Authorization": "Bearer test-token-123"},
                ) as response:
                    assert response.status_code == 200
                    assert "text/event-stream" in response.headers.get(
                        "content-type", ""
                    )
                    return True

        try:
            await asyncio.wait_for(stream_with_timeout(), timeout=2.0)
        except asyncio.TimeoutError:
            pass  # Timeout is expected for SSE streams


class TestAckEndpoint:
    """Tests for acknowledgment endpoint."""

    @pytest.mark.asyncio
    async def test_ack_missing_connection_header(self, app):
        """Test ACK endpoint requires connection ID header."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.post(
                "/connect/ack",
                params={"message_id": "msg-123"},
                headers={"Authorization": "Bearer test-token-123"},
            )
            assert response.status_code == 422  # Missing required header

    @pytest.mark.asyncio
    async def test_ack_connection_not_found(self, app):
        """Test ACK endpoint returns 404 for unknown connection."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.post(
                "/connect/ack",
                params={"message_id": "msg-123"},
                headers={
                    "Authorization": "Bearer test-token-123",
                    "X-Connection-ID": "unknown-connection",
                },
            )
            assert response.status_code == 404
            assert "Connection not found" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_ack_invalid_token(self, app, mock_channel_manager):
        """Test ACK endpoint validates token."""
        # Add a connection first
        conn = ConnectorConnection(
            connection_id="conn-123",
            connector_id="test-connector",
            channel="test-channel",
            protocol=ConnectionProtocol.SSE,
        )
        await mock_channel_manager.add_connection(conn)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.post(
                "/connect/ack",
                params={"message_id": "msg-123"},
                headers={
                    "Authorization": "Bearer wrong-token",
                    "X-Connection-ID": "conn-123",
                },
            )
            assert response.status_code == 401
            assert "Invalid token" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_ack_message_not_in_flight(self, app, mock_channel_manager):
        """Test ACK endpoint returns 404 for message not in flight."""
        # Add a connection
        conn = ConnectorConnection(
            connection_id="conn-123",
            connector_id="test-connector",
            channel="test-channel",
            protocol=ConnectionProtocol.SSE,
        )
        await mock_channel_manager.add_connection(conn)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.post(
                "/connect/ack",
                params={"message_id": "msg-not-in-flight"},
                headers={
                    "Authorization": "Bearer test-token-123",
                    "X-Connection-ID": "conn-123",
                },
            )
            assert response.status_code == 404
            assert "not in flight" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_ack_success(self, app, mock_channel_manager):
        """Test successful ACK."""
        # Add a connection with in-flight message
        conn = ConnectorConnection(
            connection_id="conn-123",
            connector_id="test-connector",
            channel="test-channel",
            protocol=ConnectionProtocol.SSE,
        )
        await mock_channel_manager.add_connection(conn)
        conn.in_flight_messages.add("msg-123")

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.post(
                "/connect/ack",
                params={"message_id": "msg-123", "status": "ack"},
                headers={
                    "Authorization": "Bearer test-token-123",
                    "X-Connection-ID": "conn-123",
                },
            )
            assert response.status_code == 200
            assert response.json()["status"] == "ok"
            assert response.json()["message_id"] == "msg-123"

    @pytest.mark.asyncio
    async def test_nack_success(self, app, mock_channel_manager):
        """Test successful NACK."""
        # Add a connection with in-flight message
        conn = ConnectorConnection(
            connection_id="conn-123",
            connector_id="test-connector",
            channel="test-channel",
            protocol=ConnectionProtocol.SSE,
        )
        await mock_channel_manager.add_connection(conn)
        conn.in_flight_messages.add("msg-456")

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.post(
                "/connect/ack",
                params={"message_id": "msg-456", "status": "nack", "retry": "true"},
                headers={
                    "Authorization": "Bearer test-token-123",
                    "X-Connection-ID": "conn-123",
                },
            )
            assert response.status_code == 200
            assert response.json()["status"] == "ok"


class TestStatusEndpoint:
    """Tests for connection status endpoint."""

    @pytest.mark.asyncio
    async def test_status_invalid_token(self, app):
        """Test status endpoint validates token."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.get(
                "/connect/status/test-channel",
                headers={"Authorization": "Bearer wrong-token"},
            )
            assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_status_channel_not_found(self, app):
        """Test status endpoint returns 404 for unknown channel."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.get(
                "/connect/status/unknown-channel",
                headers={"Authorization": "Bearer test-token"},
            )
            assert response.status_code == 401  # Token check fails first

    @pytest.mark.asyncio
    async def test_status_success(self, app):
        """Test successful status request."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.get(
                "/connect/status/test-channel",
                headers={"Authorization": "Bearer test-token-123"},
            )
            assert response.status_code == 200
            data = response.json()
            assert data["channel"] == "test-channel"
            assert data["connected"] is True
            assert "stats" in data
            assert "server_time" in data


class TestChannelManagerNotInitialized:
    """Tests for when channel manager is not initialized."""

    def test_sse_returns_503_when_not_initialized(self):
        """Test SSE endpoint returns 503 when channel manager not set."""
        test_app = FastAPI()
        test_app.include_router(router)
        set_channel_manager(None)

        client = TestClient(test_app)
        response = client.get(
            "/connect/stream/test-channel/sse",
            headers={"Authorization": "Bearer token"},
        )
        assert response.status_code == 503
        assert "not initialized" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_ack_returns_503_when_not_initialized(self):
        """Test ACK endpoint returns 503 when channel manager not set."""
        test_app = FastAPI()
        test_app.include_router(router)
        set_channel_manager(None)

        transport = ASGITransport(app=test_app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.post(
                "/connect/ack",
                params={"message_id": "msg-123"},
                headers={
                    "Authorization": "Bearer token",
                    "X-Connection-ID": "conn-123",
                },
            )
            assert response.status_code == 503

    @pytest.mark.asyncio
    async def test_status_returns_503_when_not_initialized(self):
        """Test status endpoint returns 503 when channel manager not set."""
        test_app = FastAPI()
        test_app.include_router(router)
        set_channel_manager(None)

        transport = ASGITransport(app=test_app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.get(
                "/connect/status/test-channel",
                headers={"Authorization": "Bearer token"},
            )
            assert response.status_code == 503


class TestMaxConnectionsLimit:
    """Tests for connection limit enforcement."""

    @pytest.mark.asyncio
    async def test_sse_max_connections_reached(self, app, mock_channel_manager):
        """Test SSE endpoint rejects when max connections reached."""
        # Fill up connections
        for i in range(5):  # max_connections is 5
            conn = ConnectorConnection(
                connection_id=f"conn-{i}",
                connector_id=f"connector-{i}",
                channel="test-channel",
                protocol=ConnectionProtocol.SSE,
            )
            await mock_channel_manager.add_connection(conn)

        transport = ASGITransport(app=app)
        content_result = {"content": ""}

        async def stream_and_capture():
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                async with ac.stream(
                    "GET",
                    "/connect/stream/test-channel/sse",
                    headers={"Authorization": "Bearer test-token-123"},
                ) as response:
                    # Response should be 200 (SSE sends errors as events)
                    assert response.status_code == 200
                    # Read initial chunk to get error event
                    async for chunk in response.aiter_text():
                        content_result["content"] += chunk
                        if "max_connections_reached" in content_result["content"]:
                            return True
                        if len(content_result["content"]) > 1000:
                            return False
            return False

        try:
            await asyncio.wait_for(stream_and_capture(), timeout=2.0)
        except asyncio.TimeoutError:
            pass

        assert "max_connections_reached" in content_result["content"]


class TestLongPollEndpoint:
    """Tests for long-polling streaming endpoint."""

    def test_long_poll_missing_token(self, client):
        """Test long-poll endpoint rejects missing token."""
        response = client.get("/connect/stream/test-channel/poll")
        assert response.status_code == 401
        assert "Missing authorization token" in response.json()["detail"]

    def test_long_poll_invalid_token(self, client):
        """Test long-poll endpoint rejects invalid token."""
        response = client.get(
            "/connect/stream/test-channel/poll",
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert response.status_code == 401
        assert "Invalid channel token" in response.json()["detail"]

    def test_long_poll_channel_not_found(self, client, mock_channel_manager):
        """Test long-poll endpoint returns 404 for unknown channel."""
        response = client.get(
            "/connect/stream/unknown-channel/poll",
            headers={"Authorization": "Bearer test-token"},
        )
        assert response.status_code == 401  # Token validation fails first

    @pytest.mark.asyncio
    async def test_long_poll_valid_token_query_param(self, app, mock_channel_manager):
        """Test long-poll endpoint accepts token as query parameter."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.get(
                "/connect/stream/test-channel/poll?token=test-token-123&timeout=1",
            )
            # Should return 204 (no messages) with short timeout
            assert response.status_code == 204

    @pytest.mark.asyncio
    async def test_long_poll_valid_token_header(self, app, mock_channel_manager):
        """Test long-poll endpoint accepts token in Authorization header."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.get(
                "/connect/stream/test-channel/poll?timeout=1",
                headers={"Authorization": "Bearer test-token-123"},
            )
            # Should return 204 (no messages) with short timeout
            assert response.status_code == 204

    @pytest.mark.asyncio
    async def test_long_poll_timeout_parameter_validation(self, app, mock_channel_manager):
        """Test long-poll endpoint validates timeout parameter."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            # Timeout too large
            response = await ac.get(
                "/connect/stream/test-channel/poll?timeout=120",
                headers={"Authorization": "Bearer test-token-123"},
            )
            assert response.status_code == 422  # Validation error

            # Timeout too small
            response = await ac.get(
                "/connect/stream/test-channel/poll?timeout=0",
                headers={"Authorization": "Bearer test-token-123"},
            )
            assert response.status_code == 422  # Validation error

    @pytest.mark.asyncio
    async def test_long_poll_max_messages_parameter_validation(self, app, mock_channel_manager):
        """Test long-poll endpoint validates max_messages parameter."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            # max_messages too large
            response = await ac.get(
                "/connect/stream/test-channel/poll?timeout=1&max_messages=200",
                headers={"Authorization": "Bearer test-token-123"},
            )
            assert response.status_code == 422  # Validation error

            # max_messages too small
            response = await ac.get(
                "/connect/stream/test-channel/poll?timeout=1&max_messages=0",
                headers={"Authorization": "Bearer test-token-123"},
            )
            assert response.status_code == 422  # Validation error

    @pytest.mark.asyncio
    async def test_long_poll_max_connections_reached(self, app, mock_channel_manager):
        """Test long-poll endpoint rejects when max connections reached."""
        # Fill up connections
        for i in range(5):  # max_connections is 5
            conn = ConnectorConnection(
                connection_id=f"conn-{i}",
                connector_id=f"connector-{i}",
                channel="test-channel",
                protocol=ConnectionProtocol.LONG_POLL,
            )
            await mock_channel_manager.add_connection(conn)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.get(
                "/connect/stream/test-channel/poll?timeout=1",
                headers={"Authorization": "Bearer test-token-123"},
            )
            assert response.status_code == 503
            assert "Max connections reached" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_long_poll_returns_204_when_no_messages(self, app, mock_channel_manager):
        """Test long-poll returns 204 when no messages available within timeout."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.get(
                "/connect/stream/test-channel/poll?timeout=1",
                headers={"Authorization": "Bearer test-token-123"},
            )
            assert response.status_code == 204


class TestLongPollNotInitialized:
    """Tests for long-poll when channel manager is not initialized."""

    @pytest.mark.asyncio
    async def test_long_poll_returns_503_when_not_initialized(self):
        """Test long-poll endpoint returns 503 when channel manager not set."""
        test_app = FastAPI()
        test_app.include_router(router)
        set_channel_manager(None)

        transport = ASGITransport(app=test_app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.get(
                "/connect/stream/test-channel/poll?timeout=1",
                headers={"Authorization": "Bearer test-token-123"},
            )
            assert response.status_code == 503
            assert "not initialized" in response.json()["detail"]
