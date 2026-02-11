"""
Security audit tests for per-webhook queues feature.

Validates that per-webhook routing does not introduce:
- Cross-channel message leakage
- Unbounded resource creation
- Consumer lifecycle leaks
- Queue depth reporting inconsistencies
"""

import asyncio
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

from src.webhook_connect.buffer.rabbitmq_buffer import RabbitMQBuffer
from src.webhook_connect.buffer.redis_buffer import RedisBuffer
from src.webhook_connect.channel_manager import ChannelManager
from src.webhook_connect.models import (
    ConnectorConnection,
    ConnectionProtocol,
    ConnectionState,
    ChannelConfig,
)


class TestRoutingKeyIsolation:
    """Ensure routing keys isolate channels from each other."""

    @pytest.mark.asyncio
    async def test_different_channels_have_different_routing_keys(self):
        """Two different channels must produce non-overlapping routing keys."""
        buffer = RabbitMQBuffer()
        key_a = buffer._routing_key("relay.user-AAA", "wh-1")
        key_b = buffer._routing_key("relay.user-BBB", "wh-1")
        assert key_a != key_b

    @pytest.mark.asyncio
    async def test_wildcard_scoped_to_channel(self):
        """Wildcard routing key must be scoped to a single channel."""
        buffer = RabbitMQBuffer()
        wildcard = buffer._routing_key("relay.user-AAA", "*")
        assert wildcard == "relay.user-AAA.*"
        # Should NOT match relay.user-BBB.wh-1
        assert not wildcard.startswith("relay.user-BBB")

    @pytest.mark.asyncio
    async def test_queue_names_unique_per_webhook(self):
        """Two webhooks in the same channel have distinct queue names."""
        buffer = RabbitMQBuffer(exchange_name="wc")
        q1 = buffer._queue_name("ch", "wh-1")
        q2 = buffer._queue_name("ch", "wh-2")
        assert q1 != q2

    @pytest.mark.asyncio
    async def test_redis_stream_keys_unique_per_webhook(self):
        """Two webhooks in the same channel have distinct stream keys."""
        buffer = RedisBuffer(prefix="wc")
        k1 = buffer._stream_key("ch", "wh-1")
        k2 = buffer._stream_key("ch", "wh-2")
        assert k1 != k2


class TestConsumerLifecycleSafety:
    """Ensure consumer lifecycle does not leak resources."""

    @pytest.mark.asyncio
    async def test_consumer_tag_cleaned_up_on_last_disconnect(self):
        """_consumer_tags dict is empty after all clients disconnect."""
        buffer = AsyncMock()
        buffer.subscribe = AsyncMock(return_value="ctag-1")
        buffer.unsubscribe = AsyncMock()
        buffer.nack = AsyncMock(return_value=True)
        buffer.ensure_channel = AsyncMock()
        manager = ChannelManager(buffer)

        config = ChannelConfig(
            name="ch", webhook_id="wh-1", channel_token="tok",
            heartbeat_interval=timedelta(seconds=30),
        )
        manager.channels["ch"] = config
        manager.channel_connections["ch"] = set()

        # Connect
        conn = ConnectorConnection(
            connection_id="c1", connector_id="client", channel="ch",
            protocol=ConnectionProtocol.WEBSOCKET,
        )
        conn.last_heartbeat_at = datetime.now(timezone.utc)
        await manager.add_connection(conn)
        assert len(manager._consumer_tags) == 1

        # Disconnect
        await manager.remove_connection("c1")
        assert len(manager._consumer_tags) == 0

    @pytest.mark.asyncio
    async def test_send_fn_cleaned_up_on_disconnect(self):
        """_connection_send_fns dict is cleaned after disconnect."""
        buffer = AsyncMock()
        buffer.subscribe = AsyncMock(return_value="ctag-1")
        buffer.unsubscribe = AsyncMock()
        buffer.nack = AsyncMock(return_value=True)
        manager = ChannelManager(buffer)

        config = ChannelConfig(
            name="ch", webhook_id="wh-1", channel_token="tok",
            heartbeat_interval=timedelta(seconds=30),
        )
        manager.channels["ch"] = config
        manager.channel_connections["ch"] = set()

        conn = ConnectorConnection(
            connection_id="c1", connector_id="client", channel="ch",
            protocol=ConnectionProtocol.WEBSOCKET,
        )
        conn.last_heartbeat_at = datetime.now(timezone.utc)

        manager.register_send_fn("c1", AsyncMock())
        await manager.add_connection(conn)
        assert "c1" in manager._connection_send_fns

        await manager.remove_connection("c1")
        assert "c1" not in manager._connection_send_fns

    @pytest.mark.asyncio
    async def test_redis_consumer_task_cleaned_on_unsubscribe(self):
        """Redis consumer task is removed from dict after unsubscribe."""
        buffer = RedisBuffer()
        buffer.redis = AsyncMock()

        # Create a simple never-ending task
        async def forever():
            await asyncio.sleep(3600)

        task = asyncio.create_task(forever())
        buffer._consumer_tasks["tag-1"] = task

        await buffer.unsubscribe("tag-1")

        assert "tag-1" not in buffer._consumer_tasks
        assert task.cancelled() or task.done()


class TestWebhookIdTracking:
    """Ensure _channel_webhook_ids is maintained correctly."""

    @pytest.mark.asyncio
    async def test_webhook_ids_accumulate(self):
        """Multiple register_channel calls accumulate webhook_ids."""
        buffer = AsyncMock()
        buffer.ensure_channel = AsyncMock()
        manager = ChannelManager(buffer)
        manager._eviction_task = None

        await manager.register_channel("ch", "wh-1", "tok", ttl=timedelta(hours=1))
        await manager.register_channel("ch", "wh-2", "tok", ttl=timedelta(hours=1))
        await manager.register_channel("ch", "wh-3", "tok", ttl=timedelta(hours=1))

        assert manager._channel_webhook_ids["ch"] == {"wh-1", "wh-2", "wh-3"}

    @pytest.mark.asyncio
    async def test_webhook_ids_no_duplicates(self):
        """Registering same webhook_id twice does not duplicate."""
        buffer = AsyncMock()
        buffer.ensure_channel = AsyncMock()
        manager = ChannelManager(buffer)
        manager._eviction_task = None

        await manager.register_channel("ch", "wh-1", "tok", ttl=timedelta(hours=1))
        await manager.register_channel("ch", "wh-1", "tok", ttl=timedelta(hours=1))

        assert len(manager._channel_webhook_ids["ch"]) == 1

    @pytest.mark.asyncio
    async def test_unregister_clears_webhook_ids(self):
        """Unregistering channel removes webhook_ids tracking."""
        buffer = AsyncMock()
        buffer.ensure_channel = AsyncMock()
        buffer.delete_channel = AsyncMock(return_value=True)
        manager = ChannelManager(buffer)
        manager._eviction_task = None

        await manager.register_channel("ch", "wh-1", "tok", ttl=timedelta(hours=1))
        assert "ch" in manager._channel_webhook_ids

        await manager.unregister_channel("ch")
        assert "ch" not in manager._channel_webhook_ids


class TestDeliveryCallbackFailureSafety:
    """Ensure delivery callback handles failures safely."""

    @pytest.mark.asyncio
    async def test_all_connections_fail_raises_for_requeue(self):
        """When all send_fns fail, last error is raised for buffer requeue."""
        buffer = AsyncMock()
        manager = ChannelManager(buffer)

        config = ChannelConfig(
            name="ch", webhook_id="wh-1", channel_token="tok",
            heartbeat_interval=timedelta(seconds=30),
        )
        manager.channels["ch"] = config
        manager.channel_connections["ch"] = {"c1"}

        conn = ConnectorConnection(
            connection_id="c1", connector_id="client", channel="ch",
            protocol=ConnectionProtocol.WEBSOCKET,
        )
        conn.state = ConnectionState.CONNECTED
        manager.connections["c1"] = conn

        # Send fn raises
        manager.register_send_fn("c1", AsyncMock(side_effect=RuntimeError("ws dead")))

        callback = manager._make_delivery_callback("ch")
        msg = MagicMock()
        msg.message_id = "msg-1"

        with pytest.raises(RuntimeError, match="ws dead"):
            await callback(msg)

    @pytest.mark.asyncio
    async def test_no_send_fn_raises_runtime_error(self):
        """Connection without send_fn raises RuntimeError."""
        buffer = AsyncMock()
        manager = ChannelManager(buffer)

        config = ChannelConfig(
            name="ch", webhook_id="wh-1", channel_token="tok",
            heartbeat_interval=timedelta(seconds=30),
        )
        manager.channels["ch"] = config
        manager.channel_connections["ch"] = {"c1"}

        conn = ConnectorConnection(
            connection_id="c1", connector_id="client", channel="ch",
            protocol=ConnectionProtocol.WEBSOCKET,
        )
        conn.state = ConnectionState.CONNECTED
        manager.connections["c1"] = conn
        # No send_fn registered

        callback = manager._make_delivery_callback("ch")
        msg = MagicMock()
        msg.message_id = "msg-1"

        with pytest.raises(RuntimeError, match="No send function"):
            await callback(msg)
