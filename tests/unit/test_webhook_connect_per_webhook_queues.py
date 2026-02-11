"""
Tests for per-webhook queues feature.

Validates:
- Per-webhook queue naming and routing in RabbitMQ buffer
- Per-webhook stream naming and routing in Redis buffer
- Deferred consumption (subscribe on connect, unsubscribe on disconnect)
- Per-webhook queue depth reporting
- Delivery callback round-robin logic
- Admin API webhook stats endpoint
"""

import asyncio
import json
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from src.webhook_connect.buffer.rabbitmq_buffer import RabbitMQBuffer
from src.webhook_connect.buffer.redis_buffer import (
    RedisBuffer,
    STREAM_DISCOVERY_INTERVAL,
)
from src.webhook_connect.channel_manager import ChannelManager
from src.webhook_connect.models import (
    ConnectorConnection,
    ConnectionProtocol,
    ConnectionState,
    ChannelConfig,
    WebhookMessage,
)


# ─── RabbitMQ Per-Webhook Queue Tests ────────────────────────────────────────


class TestRabbitMQPerWebhookNaming:
    """Tests for per-webhook queue and routing key naming."""

    @pytest.mark.asyncio
    async def test_queue_name_with_webhook_id(self):
        """Per-webhook queue name includes webhook_id."""
        buffer = RabbitMQBuffer(exchange_name="webhook_connect")
        name = buffer._queue_name("relay.user-123", "wh-abc")
        assert name == "webhook_connect.relay.user-123.wh-abc"

    @pytest.mark.asyncio
    async def test_queue_name_without_webhook_id(self):
        """Channel-level queue name has no webhook_id suffix."""
        buffer = RabbitMQBuffer(exchange_name="webhook_connect")
        name = buffer._queue_name("relay.user-123")
        assert name == "webhook_connect.relay.user-123"

    @pytest.mark.asyncio
    async def test_dlq_name_with_webhook_id(self):
        """Per-webhook DLQ name includes webhook_id."""
        buffer = RabbitMQBuffer(exchange_name="webhook_connect")
        name = buffer._dlq_name("relay.user-123", "wh-abc")
        assert name == "webhook_connect.relay.user-123.wh-abc.dlq"

    @pytest.mark.asyncio
    async def test_dlq_name_without_webhook_id(self):
        """Channel-level DLQ name has no webhook_id suffix."""
        buffer = RabbitMQBuffer(exchange_name="webhook_connect")
        name = buffer._dlq_name("relay.user-123")
        assert name == "webhook_connect.relay.user-123.dlq"

    @pytest.mark.asyncio
    async def test_collector_name(self):
        """Collector queue name follows convention."""
        buffer = RabbitMQBuffer(exchange_name="webhook_connect")
        name = buffer._collector_name("relay.user-123")
        assert name == "webhook_connect.relay.user-123.collector"

    @pytest.mark.asyncio
    async def test_routing_key_with_webhook_id(self):
        """Routing key includes specific webhook_id."""
        buffer = RabbitMQBuffer()
        key = buffer._routing_key("relay.user-123", "wh-abc")
        assert key == "relay.user-123.wh-abc"

    @pytest.mark.asyncio
    async def test_routing_key_wildcard(self):
        """Routing key with wildcard for subscribing to all webhooks."""
        buffer = RabbitMQBuffer()
        key = buffer._routing_key("relay.user-123", "*")
        assert key == "relay.user-123.*"

    @pytest.mark.asyncio
    async def test_routing_key_default_wildcard(self):
        """Default routing key uses wildcard."""
        buffer = RabbitMQBuffer()
        key = buffer._routing_key("relay.user-123")
        assert key == "relay.user-123.*"


class TestRabbitMQEnsureChannel:
    """Tests for ensure_channel with per-webhook queue creation."""

    @pytest.mark.asyncio
    async def test_ensure_channel_with_webhook_id_creates_queue(self):
        """ensure_channel with webhook_id declares queue bound to exchange."""
        buffer = RabbitMQBuffer(exchange_name="webhook_connect")

        # Mock channel and exchange
        mock_channel = AsyncMock()
        mock_exchange = AsyncMock()
        mock_dlx_exchange = AsyncMock()
        buffer.channel = mock_channel
        buffer.exchange = mock_exchange
        buffer.dlx_exchange = mock_dlx_exchange

        mock_queue = AsyncMock()
        mock_dlq = AsyncMock()
        mock_channel.declare_queue = AsyncMock(side_effect=[mock_dlq, mock_queue])

        await buffer.ensure_channel("relay.user-123", ttl_seconds=3600, webhook_id="wh-abc")

        # Should have declared 2 queues (DLQ + main)
        assert mock_channel.declare_queue.call_count == 2

        # DLQ call
        dlq_call = mock_channel.declare_queue.call_args_list[0]
        assert dlq_call[0][0] == "webhook_connect.relay.user-123.wh-abc.dlq"

        # Main queue call
        main_call = mock_channel.declare_queue.call_args_list[1]
        assert main_call[0][0] == "webhook_connect.relay.user-123.wh-abc"
        assert main_call[1]["arguments"]["x-message-ttl"] == 3600 * 1000

    @pytest.mark.asyncio
    async def test_ensure_channel_without_webhook_id_is_noop(self):
        """ensure_channel without webhook_id is a no-op."""
        buffer = RabbitMQBuffer()
        mock_channel = AsyncMock()
        buffer.channel = mock_channel

        await buffer.ensure_channel("relay.user-123", ttl_seconds=3600)

        # Should not declare any queues
        mock_channel.declare_queue.assert_not_called()

    @pytest.mark.asyncio
    async def test_ensure_channel_initializes_stats(self):
        """ensure_channel creates stats entry for the channel."""
        buffer = RabbitMQBuffer()
        mock_channel = AsyncMock()
        buffer.channel = mock_channel

        await buffer.ensure_channel("relay.user-123")

        assert "relay.user-123" in buffer._stats
        assert buffer._stats["relay.user-123"]["delivered"] == 0


class TestRabbitMQPushRouting:
    """Tests for push() routing to per-webhook queues."""

    @pytest.mark.asyncio
    async def test_push_routes_by_webhook_id(self):
        """push() uses webhook_id in routing key."""
        buffer = RabbitMQBuffer(exchange_name="webhook_connect")
        mock_exchange = AsyncMock()
        buffer.exchange = mock_exchange

        msg = MagicMock(spec=WebhookMessage)
        msg.message_id = "msg-1"
        msg.webhook_id = "wh-abc"
        msg.received_at = datetime.now(timezone.utc)
        msg.to_envelope.return_value = {"message_id": "msg-1", "webhook_id": "wh-abc"}

        await buffer.push("relay.user-123", msg)

        mock_exchange.publish.assert_called_once()
        call_kwargs = mock_exchange.publish.call_args
        assert call_kwargs[1]["routing_key"] == "relay.user-123.wh-abc"


class TestRabbitMQSubscribeCollector:
    """Tests for subscribe() with collector queue pattern."""

    @pytest.mark.asyncio
    async def test_subscribe_creates_collector_queue(self):
        """subscribe() creates auto-delete collector queue."""
        buffer = RabbitMQBuffer(exchange_name="webhook_connect")
        mock_channel = AsyncMock()
        mock_exchange = AsyncMock()
        buffer.channel = mock_channel
        buffer.exchange = mock_exchange

        mock_queue = AsyncMock()
        mock_queue.consume = AsyncMock(return_value="ctag-1")
        mock_channel.declare_queue = AsyncMock(return_value=mock_queue)

        callback = AsyncMock()
        tag = await buffer.subscribe("relay.user-123", callback)

        assert tag == "ctag-1"

        # Verify collector queue declaration
        mock_channel.declare_queue.assert_called_once()
        call_args = mock_channel.declare_queue.call_args
        assert call_args[0][0] == "webhook_connect.relay.user-123.collector"
        assert call_args[1]["durable"] is False
        assert call_args[1]["auto_delete"] is True

        # Verify wildcard binding
        mock_queue.bind.assert_called_once_with(
            mock_exchange, routing_key="relay.user-123.*"
        )

    @pytest.mark.asyncio
    async def test_subscribe_returns_consumer_tag(self):
        """subscribe() returns the consumer tag for cancellation."""
        buffer = RabbitMQBuffer()
        mock_channel = AsyncMock()
        mock_exchange = AsyncMock()
        buffer.channel = mock_channel
        buffer.exchange = mock_exchange

        mock_queue = AsyncMock()
        mock_queue.consume = AsyncMock(return_value="my-tag-123")
        mock_channel.declare_queue = AsyncMock(return_value=mock_queue)

        tag = await buffer.subscribe("ch", AsyncMock())
        assert tag == "my-tag-123"


class TestRabbitMQUnsubscribe:
    """Tests for unsubscribe() consumer cancellation."""

    @pytest.mark.asyncio
    async def test_unsubscribe_cancels_consumer(self):
        """unsubscribe() calls basic_cancel on the channel."""
        buffer = RabbitMQBuffer()
        buffer.channel = AsyncMock()

        await buffer.unsubscribe("ctag-1")

        buffer.channel.basic_cancel.assert_called_once_with("ctag-1")

    @pytest.mark.asyncio
    async def test_unsubscribe_no_channel_is_noop(self):
        """unsubscribe() when not connected does not raise."""
        buffer = RabbitMQBuffer()
        buffer.channel = None

        await buffer.unsubscribe("ctag-1")  # Should not raise


class TestRabbitMQGetQueueDepth:
    """Tests for get_queue_depth with per-webhook support."""

    @pytest.mark.asyncio
    async def test_get_queue_depth_with_webhook_id(self):
        """get_queue_depth queries specific per-webhook queue."""
        buffer = RabbitMQBuffer(exchange_name="webhook_connect")
        mock_channel = AsyncMock()
        buffer.channel = mock_channel

        mock_queue = AsyncMock()
        mock_declaration = MagicMock()
        mock_declaration.message_count = 42
        mock_queue.declare = AsyncMock(return_value=mock_declaration)
        mock_channel.get_queue = AsyncMock(return_value=mock_queue)

        count = await buffer.get_queue_depth("relay.user-123", webhook_id="wh-abc")

        assert count == 42
        mock_channel.get_queue.assert_called_with(
            "webhook_connect.relay.user-123.wh-abc", ensure=False
        )


class TestRabbitMQDeleteChannel:
    """Tests for delete_channel with per-webhook queue cleanup."""

    @pytest.mark.asyncio
    async def test_delete_channel_deletes_per_webhook_queues(self):
        """delete_channel removes each per-webhook queue and DLQ."""
        buffer = RabbitMQBuffer(exchange_name="webhook_connect")
        mock_channel = AsyncMock()
        buffer.channel = mock_channel

        await buffer.delete_channel(
            "relay.user-123",
            webhook_ids=["wh-1", "wh-2"],
        )

        # Should delete 2 main queues + 2 DLQs + 1 collector = 5 queue_delete calls
        queue_delete_calls = mock_channel.queue_delete.call_args_list
        deleted_names = [c[0][0] for c in queue_delete_calls]

        assert "webhook_connect.relay.user-123.wh-1" in deleted_names
        assert "webhook_connect.relay.user-123.wh-1.dlq" in deleted_names
        assert "webhook_connect.relay.user-123.wh-2" in deleted_names
        assert "webhook_connect.relay.user-123.wh-2.dlq" in deleted_names
        assert "webhook_connect.relay.user-123.collector" in deleted_names


# ─── Redis Per-Webhook Stream Tests ──────────────────────────────────────────


class TestRedisPerWebhookNaming:
    """Tests for per-webhook stream key naming."""

    @pytest.mark.asyncio
    async def test_stream_key_with_webhook_id(self):
        """Per-webhook stream key includes webhook_id."""
        buffer = RedisBuffer(prefix="webhook_connect")
        key = buffer._stream_key("relay.user-123", "wh-abc")
        assert key == "webhook_connect:stream:relay.user-123:wh-abc"

    @pytest.mark.asyncio
    async def test_stream_key_without_webhook_id(self):
        """Channel-level stream key has no webhook_id suffix."""
        buffer = RedisBuffer(prefix="webhook_connect")
        key = buffer._stream_key("relay.user-123")
        assert key == "webhook_connect:stream:relay.user-123"

    @pytest.mark.asyncio
    async def test_dlq_key_with_webhook_id(self):
        """Per-webhook DLQ key includes webhook_id."""
        buffer = RedisBuffer(prefix="webhook_connect")
        key = buffer._dlq_key("relay.user-123", "wh-abc")
        assert key == "webhook_connect:dlq:relay.user-123:wh-abc"


class TestRedisSubscribeUnsubscribe:
    """Tests for Redis subscribe with background task pattern."""

    @pytest.mark.asyncio
    async def test_subscribe_returns_consumer_tag(self):
        """subscribe() returns a consumer tag string."""
        buffer = RedisBuffer()
        buffer.redis = AsyncMock()
        buffer.redis.scan_iter = MagicMock(return_value=AsyncIterHelper([]))

        callback = AsyncMock()
        tag = await buffer.subscribe("ch", callback)

        assert tag is not None
        assert isinstance(tag, str)
        assert tag.startswith("consumer_")

    @pytest.mark.asyncio
    async def test_subscribe_creates_task(self):
        """subscribe() stores a background task for the consumer."""
        buffer = RedisBuffer()
        buffer.redis = AsyncMock()
        buffer.redis.scan_iter = MagicMock(return_value=AsyncIterHelper([]))

        tag = await buffer.subscribe("ch", AsyncMock())

        assert tag in buffer._consumer_tasks
        assert isinstance(buffer._consumer_tasks[tag], asyncio.Task)

        # Cleanup
        buffer._consumer_tasks[tag].cancel()
        try:
            await buffer._consumer_tasks[tag]
        except asyncio.CancelledError:
            pass

    @pytest.mark.asyncio
    async def test_unsubscribe_cancels_task(self):
        """unsubscribe() cancels the background consumer task."""
        buffer = RedisBuffer()
        buffer.redis = AsyncMock()
        buffer.redis.scan_iter = MagicMock(return_value=AsyncIterHelper([]))

        tag = await buffer.subscribe("ch", AsyncMock())

        assert tag in buffer._consumer_tasks
        task = buffer._consumer_tasks[tag]

        await buffer.unsubscribe(tag)

        assert tag not in buffer._consumer_tasks
        assert task.cancelled() or task.done()

    @pytest.mark.asyncio
    async def test_unsubscribe_unknown_tag_is_noop(self):
        """unsubscribe() with unknown tag does not raise."""
        buffer = RedisBuffer()
        await buffer.unsubscribe("nonexistent-tag")  # Should not raise


class TestRedisGetQueueDepth:
    """Tests for Redis get_queue_depth with per-webhook support."""

    @pytest.mark.asyncio
    async def test_get_queue_depth_with_webhook_id(self):
        """get_queue_depth queries specific per-webhook stream."""
        buffer = RedisBuffer(prefix="webhook_connect")
        buffer.redis = AsyncMock()
        buffer.redis.xinfo_stream = AsyncMock(return_value={"length": 15})

        count = await buffer.get_queue_depth("relay.user-123", webhook_id="wh-abc")

        assert count == 15
        buffer.redis.xinfo_stream.assert_called_with(
            "webhook_connect:stream:relay.user-123:wh-abc"
        )


class TestRedisDeleteChannel:
    """Tests for Redis delete_channel with per-webhook cleanup."""

    @pytest.mark.asyncio
    async def test_delete_channel_deletes_per_webhook_keys(self):
        """delete_channel removes per-webhook streams, DLQs, and meta keys."""
        buffer = RedisBuffer(prefix="webhook_connect")
        buffer.redis = AsyncMock()

        await buffer.delete_channel(
            "relay.user-123",
            webhook_ids=["wh-1", "wh-2"],
        )

        buffer.redis.delete.assert_called_once()
        deleted_keys = buffer.redis.delete.call_args[0]

        assert "webhook_connect:stream:relay.user-123:wh-1" in deleted_keys
        assert "webhook_connect:dlq:relay.user-123:wh-1" in deleted_keys
        assert "webhook_connect:stream:relay.user-123:wh-2" in deleted_keys
        assert "webhook_connect:dlq:relay.user-123:wh-2" in deleted_keys
        # Also channel-level keys
        assert "webhook_connect:stream:relay.user-123" in deleted_keys
        assert "webhook_connect:dlq:relay.user-123" in deleted_keys


# ─── Channel Manager Deferred Consumption Tests ─────────────────────────────


class TestDeferredConsumption:
    """Tests for deferred consumption (subscribe on connect, unsubscribe on disconnect)."""

    def _make_channel_manager(self):
        """Create a ChannelManager with mock buffer."""
        buffer = AsyncMock()
        buffer.connect = AsyncMock()
        buffer.close = AsyncMock()
        buffer.health_check = AsyncMock(return_value=True)
        buffer.nack = AsyncMock(return_value=True)
        buffer.subscribe = AsyncMock(return_value="ctag-test")
        buffer.unsubscribe = AsyncMock()
        buffer.ensure_channel = AsyncMock()
        buffer.get_webhook_queue_depths = AsyncMock(return_value={})
        return ChannelManager(buffer)

    def _make_config(self, name="test-ch", webhook_id="wh-1"):
        """Create a ChannelConfig."""
        return ChannelConfig(
            name=name,
            webhook_id=webhook_id,
            channel_token="tok-1",
            heartbeat_interval=timedelta(seconds=30),
        )

    def _make_connection(self, conn_id="conn-1", channel="test-ch"):
        """Create a ConnectorConnection."""
        return ConnectorConnection(
            connection_id=conn_id,
            connector_id="test-client",
            channel=channel,
            protocol=ConnectionProtocol.WEBSOCKET,
        )

    @pytest.mark.asyncio
    async def test_first_client_starts_consumer(self):
        """Buffer consumer starts when first client connects to channel."""
        manager = self._make_channel_manager()
        config = self._make_config()
        manager.channels["test-ch"] = config
        manager.channel_connections["test-ch"] = set()

        conn = self._make_connection()
        conn.last_heartbeat_at = datetime.now(timezone.utc)

        result = await manager.add_connection(conn)

        assert result is True
        assert "test-ch" in manager._consumer_tags
        assert manager._consumer_tags["test-ch"] == "ctag-test"
        manager.buffer.subscribe.assert_called_once()

    @pytest.mark.asyncio
    async def test_second_client_does_not_start_consumer(self):
        """Buffer consumer is NOT started again for additional clients."""
        manager = self._make_channel_manager()
        config = self._make_config()
        manager.channels["test-ch"] = config
        manager.channel_connections["test-ch"] = set()

        # First client
        conn1 = self._make_connection("conn-1")
        conn1.last_heartbeat_at = datetime.now(timezone.utc)
        await manager.add_connection(conn1)

        # Second client
        conn2 = self._make_connection("conn-2")
        conn2.last_heartbeat_at = datetime.now(timezone.utc)
        await manager.add_connection(conn2)

        # subscribe called only once
        assert manager.buffer.subscribe.call_count == 1

    @pytest.mark.asyncio
    async def test_last_client_disconnect_stops_consumer(self):
        """Buffer consumer stops when last client disconnects."""
        manager = self._make_channel_manager()
        config = self._make_config()
        manager.channels["test-ch"] = config
        manager.channel_connections["test-ch"] = set()

        conn = self._make_connection()
        conn.last_heartbeat_at = datetime.now(timezone.utc)
        await manager.add_connection(conn)

        assert "test-ch" in manager._consumer_tags

        await manager.remove_connection("conn-1")

        assert "test-ch" not in manager._consumer_tags
        manager.buffer.unsubscribe.assert_called_once_with("ctag-test")

    @pytest.mark.asyncio
    async def test_non_last_client_disconnect_keeps_consumer(self):
        """Consumer stays running when non-last client disconnects."""
        manager = self._make_channel_manager()
        config = self._make_config()
        manager.channels["test-ch"] = config
        manager.channel_connections["test-ch"] = set()

        # Two clients
        conn1 = self._make_connection("conn-1")
        conn1.last_heartbeat_at = datetime.now(timezone.utc)
        conn2 = self._make_connection("conn-2")
        conn2.last_heartbeat_at = datetime.now(timezone.utc)

        await manager.add_connection(conn1)
        await manager.add_connection(conn2)

        # Remove first client
        await manager.remove_connection("conn-1")

        # Consumer still running
        assert "test-ch" in manager._consumer_tags
        manager.buffer.unsubscribe.assert_not_called()

    @pytest.mark.asyncio
    async def test_stop_cancels_all_consumers(self):
        """stop() cancels all buffer consumers."""
        manager = self._make_channel_manager()
        manager._consumer_tags["ch-1"] = "ctag-1"
        manager._consumer_tags["ch-2"] = "ctag-2"

        # Mock eviction task
        manager._eviction_task = None

        await manager.stop()

        assert len(manager._consumer_tags) == 0
        calls = manager.buffer.unsubscribe.call_args_list
        tags_cancelled = [c[0][0] for c in calls]
        assert "ctag-1" in tags_cancelled
        assert "ctag-2" in tags_cancelled


class TestRegisterChannelWebhookId:
    """Tests for register_channel passing webhook_id to buffer."""

    @pytest.mark.asyncio
    async def test_register_channel_passes_webhook_id(self):
        """register_channel calls ensure_channel with webhook_id."""
        buffer = AsyncMock()
        buffer.ensure_channel = AsyncMock()
        manager = ChannelManager(buffer)
        manager._eviction_task = None

        await manager.register_channel(
            name="test-ch",
            webhook_id="wh-abc",
            token="tok-1",
            ttl=timedelta(hours=1),
        )

        buffer.ensure_channel.assert_called_once_with(
            "test-ch", 3600, webhook_id="wh-abc"
        )

    @pytest.mark.asyncio
    async def test_register_channel_tracks_webhook_ids(self):
        """register_channel adds webhook_id to _channel_webhook_ids."""
        buffer = AsyncMock()
        buffer.ensure_channel = AsyncMock()
        manager = ChannelManager(buffer)
        manager._eviction_task = None

        await manager.register_channel("ch", "wh-1", "tok", ttl=timedelta(hours=1))
        await manager.register_channel("ch", "wh-2", "tok", ttl=timedelta(hours=1))

        assert manager._channel_webhook_ids["ch"] == {"wh-1", "wh-2"}


class TestDeliveryCallback:
    """Tests for _make_delivery_callback message routing."""

    @pytest.mark.asyncio
    async def test_delivery_callback_sends_to_connected_client(self):
        """Delivery callback sends message to a connected client."""
        buffer = AsyncMock()
        manager = ChannelManager(buffer)

        # Set up channel with one connected client
        config = ChannelConfig(
            name="ch", webhook_id="wh-1", channel_token="tok",
            heartbeat_interval=timedelta(seconds=30),
        )
        manager.channels["ch"] = config
        manager.channel_connections["ch"] = {"conn-1"}

        conn = ConnectorConnection(
            connection_id="conn-1",
            connector_id="client",
            channel="ch",
            protocol=ConnectionProtocol.WEBSOCKET,
        )
        conn.state = ConnectionState.CONNECTED
        manager.connections["conn-1"] = conn

        # Register a mock send function
        send_fn = AsyncMock()
        manager.register_send_fn("conn-1", send_fn)

        callback = manager._make_delivery_callback("ch")
        msg = MagicMock(spec=WebhookMessage)
        msg.message_id = "msg-1"

        await callback(msg)

        send_fn.assert_called_once_with(msg)

    @pytest.mark.asyncio
    async def test_delivery_callback_nacks_when_no_clients(self):
        """Delivery callback nacks message when no clients are connected."""
        buffer = AsyncMock()
        manager = ChannelManager(buffer)

        manager.channels["ch"] = ChannelConfig(
            name="ch", webhook_id="wh-1", channel_token="tok",
            heartbeat_interval=timedelta(seconds=30),
        )
        manager.channel_connections["ch"] = set()

        callback = manager._make_delivery_callback("ch")
        msg = MagicMock(spec=WebhookMessage)
        msg.message_id = "msg-1"

        await callback(msg)

        buffer.nack.assert_called_once_with("ch", "msg-1", retry=True)

    @pytest.mark.asyncio
    async def test_delivery_callback_skips_disconnected_clients(self):
        """Delivery callback skips clients that are not CONNECTED."""
        buffer = AsyncMock()
        manager = ChannelManager(buffer)

        manager.channels["ch"] = ChannelConfig(
            name="ch", webhook_id="wh-1", channel_token="tok",
            heartbeat_interval=timedelta(seconds=30),
        )
        manager.channel_connections["ch"] = {"conn-1", "conn-2"}

        # conn-1 is disconnected
        conn1 = ConnectorConnection(
            connection_id="conn-1", connector_id="c1", channel="ch",
            protocol=ConnectionProtocol.WEBSOCKET,
        )
        conn1.state = ConnectionState.DISCONNECTED
        manager.connections["conn-1"] = conn1

        # conn-2 is connected
        conn2 = ConnectorConnection(
            connection_id="conn-2", connector_id="c2", channel="ch",
            protocol=ConnectionProtocol.WEBSOCKET,
        )
        conn2.state = ConnectionState.CONNECTED
        manager.connections["conn-2"] = conn2

        send_fn_2 = AsyncMock()
        manager.register_send_fn("conn-2", send_fn_2)

        callback = manager._make_delivery_callback("ch")
        msg = MagicMock(spec=WebhookMessage)
        msg.message_id = "msg-1"

        await callback(msg)

        send_fn_2.assert_called_once_with(msg)


class TestGetWebhookQueueDepths:
    """Tests for per-webhook queue depth reporting."""

    @pytest.mark.asyncio
    async def test_get_webhook_queue_depths_returns_depths(self):
        """get_webhook_queue_depths returns per-webhook counts."""
        buffer = AsyncMock()
        buffer.get_webhook_queue_depths = AsyncMock(
            return_value={"wh-1": 5, "wh-2": 12}
        )
        manager = ChannelManager(buffer)
        manager._channel_webhook_ids["ch"] = {"wh-1", "wh-2"}

        depths = await manager.get_webhook_queue_depths("ch")

        assert depths == {"wh-1": 5, "wh-2": 12}

    @pytest.mark.asyncio
    async def test_get_webhook_queue_depths_empty_channel(self):
        """get_webhook_queue_depths returns empty dict for unknown channel."""
        buffer = AsyncMock()
        manager = ChannelManager(buffer)

        depths = await manager.get_webhook_queue_depths("unknown")

        assert depths == {}


class TestUnregisterChannelCleanup:
    """Tests for unregister_channel cleaning up per-webhook resources."""

    @pytest.mark.asyncio
    async def test_unregister_stops_consumer_and_deletes_queues(self):
        """unregister_channel stops consumer and passes webhook_ids to delete."""
        buffer = AsyncMock()
        buffer.unsubscribe = AsyncMock()
        buffer.delete_channel = AsyncMock(return_value=True)
        manager = ChannelManager(buffer)

        config = ChannelConfig(
            name="ch", webhook_id="wh-1", channel_token="tok",
            heartbeat_interval=timedelta(seconds=30),
        )
        manager.channels["ch"] = config
        manager.channel_connections["ch"] = set()
        manager._sequence_counters["ch"] = 0
        manager._consumer_tags["ch"] = "ctag-1"
        manager._channel_webhook_ids["ch"] = {"wh-1", "wh-2"}

        result = await manager.unregister_channel("ch")

        assert result is True
        buffer.unsubscribe.assert_called_once_with("ctag-1")
        buffer.delete_channel.assert_called_once()

        # Verify webhook_ids passed as keyword argument
        call_args = buffer.delete_channel.call_args
        webhook_ids = call_args[1].get("webhook_ids")
        assert webhook_ids is not None
        assert set(webhook_ids) == {"wh-1", "wh-2"}


# ─── Async Iterator Helper ──────────────────────────────────────────────────


class AsyncIterHelper:
    """Helper to create async iterators from lists for mock scan_iter."""

    def __init__(self, items):
        self.items = items
        self.index = 0

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.index >= len(self.items):
            raise StopAsyncIteration
        item = self.items[self.index]
        self.index += 1
        return item
