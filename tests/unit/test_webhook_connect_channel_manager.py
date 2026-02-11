"""
Unit tests for Webhook Connect ChannelManager.
"""

import pytest
import asyncio
from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from src.webhook_connect.channel_manager import ChannelManager
from src.webhook_connect.models import (
    WebhookMessage,
    ChannelConfig,
    ConnectorConnection,
    ConnectionProtocol,
    ConnectionState,
)


class MockBuffer:
    """Mock message buffer for testing."""

    def __init__(self):
        self.connected = False
        self.channels = {}
        self.messages = {}
        self.stats = {}

    async def connect(self):
        self.connected = True

    async def close(self):
        self.connected = False

    async def ensure_channel(self, channel: str, ttl_seconds: int = 86400, webhook_id: str = None):
        self.channels.setdefault(channel, {"ttl": ttl_seconds, "messages": []})

    async def push(self, channel: str, message: WebhookMessage) -> bool:
        if channel not in self.channels:
            return False
        self.channels[channel]["messages"].append(message)
        return True

    async def get_queue_depth(self, channel: str, webhook_id: str = None) -> int:
        if channel not in self.channels:
            return 0
        return len(self.channels[channel]["messages"])

    async def get_webhook_queue_depths(self, channel, webhook_ids):
        return {}

    async def delete_channel(self, channel: str, webhook_ids=None) -> bool:
        if channel in self.channels:
            del self.channels[channel]
            return True
        return False

    async def subscribe(self, channel, callback, prefetch=10, webhook_ids=None):
        await asyncio.sleep(0.1)
        return f"mock-tag-{channel}"

    async def unsubscribe(self, consumer_tag):
        pass

    async def ack(self, channel: str, message_id: str) -> bool:
        return True

    async def nack(self, channel: str, message_id: str, retry: bool = True) -> bool:
        return True

    async def get_stats(self, channel: str):
        from src.webhook_connect.models import ChannelStats

        return ChannelStats(channel=channel, messages_queued=0)

    async def health_check(self) -> bool:
        return self.connected


@pytest.fixture
def mock_buffer():
    """Create a mock buffer."""
    return MockBuffer()


@pytest.fixture
async def channel_manager(mock_buffer):
    """Create a channel manager with mock buffer.

    This is an async fixture because ChannelManager creates asyncio.Lock()
    objects in __init__, which in Python 3.9 requires an event loop to exist.
    Using an async fixture ensures the event loop is available when the
    ChannelManager is instantiated.
    """
    return ChannelManager(mock_buffer)


class TestChannelManagerStartStop:
    """Tests for ChannelManager start/stop."""

    @pytest.mark.asyncio
    async def test_start(self, channel_manager, mock_buffer):
        """Test starting the channel manager."""
        await channel_manager.start()
        assert mock_buffer.connected is True

    @pytest.mark.asyncio
    async def test_stop(self, channel_manager, mock_buffer):
        """Test stopping the channel manager."""
        await channel_manager.start()
        await channel_manager.stop()
        assert mock_buffer.connected is False


class TestChannelRegistration:
    """Tests for channel registration."""

    @pytest.mark.asyncio
    async def test_register_channel(self, channel_manager):
        """Test registering a channel."""
        config = await channel_manager.register_channel(
            name="test-channel",
            webhook_id="webhook-1",
            token="secret-token",
            ttl=timedelta(hours=24),
        )

        assert config.name == "test-channel"
        assert config.webhook_id == "webhook-1"
        assert channel_manager.get_channel("test-channel") is not None

    @pytest.mark.asyncio
    async def test_register_channel_with_options(self, channel_manager):
        """Test registering a channel with custom options."""
        config = await channel_manager.register_channel(
            name="custom-channel",
            webhook_id="webhook-2",
            token="token",
            ttl=timedelta(hours=12),
            max_queue_size=5000,
            max_connections=5,
        )

        assert config.max_queue_size == 5000
        assert config.max_connections == 5

    @pytest.mark.asyncio
    async def test_unregister_channel(self, channel_manager):
        """Test unregistering a channel."""
        await channel_manager.register_channel(
            name="temp-channel",
            webhook_id="w",
            token="t",
        )

        result = await channel_manager.unregister_channel("temp-channel")
        assert result is True
        assert channel_manager.get_channel("temp-channel") is None

    @pytest.mark.asyncio
    async def test_unregister_nonexistent_channel(self, channel_manager):
        """Test unregistering a non-existent channel."""
        result = await channel_manager.unregister_channel("nonexistent")
        assert result is False

    @pytest.mark.asyncio
    async def test_list_channels(self, channel_manager):
        """Test listing channels."""
        await channel_manager.register_channel("ch1", "w1", "t1")
        await channel_manager.register_channel("ch2", "w2", "t2")

        channels = channel_manager.list_channels()
        assert "ch1" in channels
        assert "ch2" in channels
        assert len(channels) == 2


class TestTokenValidation:
    """Tests for token validation."""

    @pytest.mark.asyncio
    async def test_validate_token_success(self, channel_manager):
        """Test successful token validation."""
        await channel_manager.register_channel("ch", "w", "secret")

        assert channel_manager.validate_token("ch", "secret") is True

    @pytest.mark.asyncio
    async def test_validate_token_failure(self, channel_manager):
        """Test failed token validation."""
        await channel_manager.register_channel("ch", "w", "secret")

        assert channel_manager.validate_token("ch", "wrong") is False

    @pytest.mark.asyncio
    async def test_validate_token_unknown_channel(self, channel_manager):
        """Test token validation for unknown channel."""
        assert channel_manager.validate_token("unknown", "token") is False

    @pytest.mark.asyncio
    async def test_rotate_token(self, channel_manager):
        """Test token rotation."""
        await channel_manager.register_channel("ch", "w", "old-token")

        new_token = await channel_manager.rotate_token("ch", timedelta(hours=1))

        assert new_token is not None
        assert new_token != "old-token"
        assert new_token.startswith("ch_tok_")

        # Both tokens should be valid during grace period
        assert channel_manager.validate_token("ch", new_token) is True
        assert channel_manager.validate_token("ch", "old-token") is True


class TestMessagePublishing:
    """Tests for message publishing."""

    @pytest.mark.asyncio
    async def test_publish_message(self, channel_manager, mock_buffer):
        """Test publishing a message."""
        await channel_manager.register_channel("ch", "w", "t")

        message = WebhookMessage(
            channel="ch",
            webhook_id="w",
            payload={"test": "data"},
        )

        result = await channel_manager.publish("ch", message)
        assert result is True
        assert len(mock_buffer.channels["ch"]["messages"]) == 1

    @pytest.mark.asyncio
    async def test_publish_to_unknown_channel(self, channel_manager):
        """Test publishing to unknown channel."""
        message = WebhookMessage(
            channel="unknown",
            webhook_id="w",
            payload={},
        )

        result = await channel_manager.publish("unknown", message)
        assert result is False

    @pytest.mark.asyncio
    async def test_publish_assigns_sequence(self, channel_manager, mock_buffer):
        """Test that publishing assigns sequence numbers."""
        await channel_manager.register_channel("ch", "w", "t")

        msg1 = WebhookMessage(channel="ch", webhook_id="w", payload={})
        msg2 = WebhookMessage(channel="ch", webhook_id="w", payload={})

        await channel_manager.publish("ch", msg1)
        await channel_manager.publish("ch", msg2)

        assert msg1.sequence == 1
        assert msg2.sequence == 2


class TestConnectionManagement:
    """Tests for connection management."""

    @pytest.mark.asyncio
    async def test_add_connection(self, channel_manager):
        """Test adding a connection."""
        await channel_manager.register_channel("ch", "w", "t")

        conn = ConnectorConnection(
            connection_id="conn-1",
            connector_id="c-1",
            channel="ch",
            protocol=ConnectionProtocol.WEBSOCKET,
        )

        result = await channel_manager.add_connection(conn)
        assert result is True
        assert channel_manager.get_connection("conn-1") is not None

    @pytest.mark.asyncio
    async def test_add_connection_unknown_channel(self, channel_manager):
        """Test adding a connection to unknown channel."""
        conn = ConnectorConnection(
            connection_id="conn-1",
            connector_id="c-1",
            channel="unknown",
            protocol=ConnectionProtocol.WEBSOCKET,
        )

        result = await channel_manager.add_connection(conn)
        assert result is False

    @pytest.mark.asyncio
    async def test_max_connections_limit(self, channel_manager):
        """Test max connections limit."""
        await channel_manager.register_channel("ch", "w", "t", max_connections=2)

        conn1 = ConnectorConnection(
            connection_id="conn-1",
            connector_id="c-1",
            channel="ch",
            protocol=ConnectionProtocol.WEBSOCKET,
        )
        conn2 = ConnectorConnection(
            connection_id="conn-2",
            connector_id="c-2",
            channel="ch",
            protocol=ConnectionProtocol.WEBSOCKET,
        )
        conn3 = ConnectorConnection(
            connection_id="conn-3",
            connector_id="c-3",
            channel="ch",
            protocol=ConnectionProtocol.WEBSOCKET,
        )

        assert await channel_manager.add_connection(conn1) is True
        assert await channel_manager.add_connection(conn2) is True
        assert await channel_manager.add_connection(conn3) is False

    @pytest.mark.asyncio
    async def test_remove_connection(self, channel_manager):
        """Test removing a connection."""
        await channel_manager.register_channel("ch", "w", "t")

        conn = ConnectorConnection(
            connection_id="conn-1",
            connector_id="c-1",
            channel="ch",
            protocol=ConnectionProtocol.WEBSOCKET,
        )

        await channel_manager.add_connection(conn)
        await channel_manager.remove_connection("conn-1")

        assert channel_manager.get_connection("conn-1") is None

    @pytest.mark.asyncio
    async def test_get_channel_connections(self, channel_manager):
        """Test getting connections for a channel."""
        await channel_manager.register_channel("ch", "w", "t")

        conn1 = ConnectorConnection(
            connection_id="conn-1",
            connector_id="c-1",
            channel="ch",
            protocol=ConnectionProtocol.WEBSOCKET,
        )
        conn2 = ConnectorConnection(
            connection_id="conn-2",
            connector_id="c-2",
            channel="ch",
            protocol=ConnectionProtocol.SSE,
        )

        await channel_manager.add_connection(conn1)
        await channel_manager.add_connection(conn2)

        connections = channel_manager.get_channel_connections("ch")
        assert len(connections) == 2


class TestAcknowledgments:
    """Tests for message acknowledgments."""

    @pytest.mark.asyncio
    async def test_ack_message(self, channel_manager):
        """Test acknowledging a message."""
        await channel_manager.register_channel("ch", "w", "t")

        conn = ConnectorConnection(
            connection_id="conn-1",
            connector_id="c-1",
            channel="ch",
            protocol=ConnectionProtocol.WEBSOCKET,
        )
        await channel_manager.add_connection(conn)
        conn.in_flight_messages.add("msg-1")

        result = await channel_manager.ack_message("ch", "msg-1", "conn-1")
        assert result is True
        assert "msg-1" not in conn.in_flight_messages
        assert conn.messages_acked == 1

    @pytest.mark.asyncio
    async def test_nack_message(self, channel_manager):
        """Test negative acknowledging a message."""
        await channel_manager.register_channel("ch", "w", "t")

        conn = ConnectorConnection(
            connection_id="conn-1",
            connector_id="c-1",
            channel="ch",
            protocol=ConnectionProtocol.WEBSOCKET,
        )
        await channel_manager.add_connection(conn)
        conn.in_flight_messages.add("msg-1")

        result = await channel_manager.nack_message("ch", "msg-1", "conn-1", retry=True)
        assert result is True
        assert "msg-1" not in conn.in_flight_messages
        assert conn.messages_nacked == 1


class TestHealthCheck:
    """Tests for health check."""

    @pytest.mark.asyncio
    async def test_health_check(self, channel_manager, mock_buffer):
        """Test health check."""
        await channel_manager.start()
        await channel_manager.register_channel("ch", "w", "t")

        health = await channel_manager.health_check()

        assert health["buffer"] is True
        assert health["channels_count"] == 1
        assert health["connections_count"] == 0


class TestGetAllStats:
    """Tests for getting all channel stats."""

    @pytest.mark.asyncio
    async def test_get_all_stats(self, channel_manager):
        """Test getting stats for all channels."""
        await channel_manager.register_channel("ch1", "w1", "t1")
        await channel_manager.register_channel("ch2", "w2", "t2")

        stats = channel_manager.get_all_stats()

        assert "ch1" in stats
        assert "ch2" in stats
        assert stats["ch1"]["webhook_id"] == "w1"
        assert stats["ch2"]["webhook_id"] == "w2"
