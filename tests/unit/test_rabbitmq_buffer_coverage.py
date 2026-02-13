"""
Unit tests for RabbitMQBuffer (buffer/rabbitmq_buffer.py).

Covers missed lines including:
- connect / close lifecycle
- ensure_channel (with/without webhook_id)
- push success and failure
- subscribe, subscribe_webhook, _start_webhook_consumer
- _make_message_handler: happy path, callback failure, redelivery exhaustion
- unsubscribe (composite and single tags)
- ack / nack (retry=True, retry=False)
- get_queue_depth / get_webhook_queue_depths / get_in_flight_count / get_stats
- cleanup_expired
- delete_channel
- get_dead_letters
- health_check
"""

import asyncio
import json
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

from src.webhook_connect.buffer.rabbitmq_buffer import RabbitMQBuffer
from src.webhook_connect.models import WebhookMessage, ChannelStats, MessageState


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _make_message(**kwargs) -> WebhookMessage:
    """Create a test WebhookMessage with sensible defaults."""
    defaults = dict(
        message_id="msg-001",
        channel="ch1",
        webhook_id="wh1",
        payload={"key": "value"},
    )
    defaults.update(kwargs)
    return WebhookMessage(**defaults)


def _mock_amqp_message(message_id="msg-001", body=None, headers=None):
    """Create a mock aio_pika IncomingMessage."""
    mock = AsyncMock()
    mock.message_id = message_id
    msg = _make_message(message_id=message_id)
    mock.body = body or json.dumps(msg.to_envelope()).encode()
    mock.headers = headers or {"channel": "ch1", "webhook_id": "wh1"}
    mock.ack = AsyncMock()
    mock.reject = AsyncMock()
    return mock


def _mock_queue(consume_tag="tag-1"):
    """Create a mock aio_pika Queue."""
    q = AsyncMock()
    q.consume = AsyncMock(return_value=consume_tag)
    q.cancel = AsyncMock()
    q.declaration_result = MagicMock()
    q.declaration_result.message_count = 42
    return q


def _mock_channel():
    """Create a mock aio_pika Channel."""
    ch = AsyncMock()
    ch.set_qos = AsyncMock()
    ch.declare_exchange = AsyncMock()
    ch.declare_queue = AsyncMock(return_value=_mock_queue())
    ch.queue_delete = AsyncMock()
    ch.get_queue = AsyncMock(return_value=None)
    ch.close = AsyncMock()
    return ch


def _mock_connection(is_closed=False):
    """Create a mock aio_pika RobustConnection."""
    conn = AsyncMock()
    conn.is_closed = is_closed
    conn.close = AsyncMock()
    conn.channel = AsyncMock(return_value=_mock_channel())
    return conn


# ─── Connect / Close ─────────────────────────────────────────────────────────

class TestRabbitMQBufferConnectClose:
    """Tests for connect() and close() lifecycle."""

    @pytest.mark.asyncio
    async def test_connect_success(self):
        """Successful connect sets connection, channel, and exchanges."""
        buf = RabbitMQBuffer()
        mock_conn = _mock_connection()
        mock_ch = _mock_channel()
        mock_conn.channel.return_value = mock_ch

        mock_exchange = AsyncMock()
        mock_dlx = AsyncMock()
        mock_ch.declare_exchange.side_effect = [mock_exchange, mock_dlx]

        with patch("src.webhook_connect.buffer.rabbitmq_buffer.connect_robust", return_value=mock_conn):
            await buf.connect()

        assert buf.connection is mock_conn
        assert buf.channel is mock_ch
        assert buf.exchange is mock_exchange
        assert buf.dlx_exchange is mock_dlx

    @pytest.mark.asyncio
    async def test_connect_failure_raises(self):
        """connect() raises ConnectionError on failure."""
        buf = RabbitMQBuffer()
        with patch("src.webhook_connect.buffer.rabbitmq_buffer.connect_robust", side_effect=Exception("refused")):
            with pytest.raises(ConnectionError, match="Failed to connect"):
                await buf.connect()

    @pytest.mark.asyncio
    async def test_close_success(self):
        """close() closes connection and clears references."""
        buf = RabbitMQBuffer()
        buf.connection = _mock_connection()
        buf.channel = _mock_channel()
        buf.exchange = AsyncMock()

        await buf.close()
        assert buf.connection is None
        assert buf.channel is None
        assert buf.exchange is None

    @pytest.mark.asyncio
    async def test_close_when_not_connected(self):
        """close() is safe when not connected."""
        buf = RabbitMQBuffer()
        buf.connection = None
        await buf.close()  # Should not raise


# ─── ensure_channel ──────────────────────────────────────────────────────────

class TestRabbitMQBufferEnsureChannel:
    """Tests for ensure_channel()."""

    @pytest.mark.asyncio
    async def test_ensure_channel_not_connected_raises(self):
        """ensure_channel raises ConnectionError when not connected."""
        buf = RabbitMQBuffer()
        with pytest.raises(ConnectionError, match="Not connected"):
            await buf.ensure_channel("ch1")

    @pytest.mark.asyncio
    async def test_ensure_channel_no_webhook_id_initializes_stats(self):
        """ensure_channel without webhook_id only initializes stats."""
        buf = RabbitMQBuffer()
        buf.channel = _mock_channel()

        await buf.ensure_channel("ch1")
        assert "ch1" in buf._stats

    @pytest.mark.asyncio
    async def test_ensure_channel_no_webhook_id_idempotent(self):
        """ensure_channel without webhook_id does not overwrite existing stats."""
        buf = RabbitMQBuffer()
        buf.channel = _mock_channel()
        buf._stats["ch1"] = {"delivered": 5, "expired": 0, "dead_lettered": 0}

        await buf.ensure_channel("ch1")
        assert buf._stats["ch1"]["delivered"] == 5

    @pytest.mark.asyncio
    async def test_ensure_channel_with_webhook_id(self):
        """ensure_channel with webhook_id creates queue and DLQ."""
        buf = RabbitMQBuffer()
        buf.channel = _mock_channel()
        buf.exchange = AsyncMock()
        buf.dlx_exchange = AsyncMock()

        await buf.ensure_channel("ch1", ttl_seconds=7200, webhook_id="wh1")
        assert buf.channel.declare_queue.await_count == 2  # DLQ + main
        assert "ch1" in buf._stats


# ─── push ────────────────────────────────────────────────────────────────────

class TestRabbitMQBufferPush:
    """Tests for push()."""

    @pytest.mark.asyncio
    async def test_push_not_connected_raises(self):
        """push raises ConnectionError when not connected."""
        buf = RabbitMQBuffer()
        with pytest.raises(ConnectionError, match="Not connected"):
            await buf.push("ch1", _make_message())

    @pytest.mark.asyncio
    async def test_push_success(self):
        """push publishes message and returns True."""
        buf = RabbitMQBuffer()
        buf.exchange = AsyncMock()
        msg = _make_message()

        result = await buf.push("ch1", msg)
        assert result is True
        buf.exchange.publish.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_push_failure_returns_false(self):
        """push returns False on publish error."""
        buf = RabbitMQBuffer()
        buf.exchange = AsyncMock()
        buf.exchange.publish.side_effect = Exception("publish error")

        result = await buf.push("ch1", _make_message())
        assert result is False


# ─── _make_message_handler ───────────────────────────────────────────────────

class TestRabbitMQBufferMessageHandler:
    """Tests for _make_message_handler()."""

    @pytest.mark.asyncio
    async def test_handler_happy_path(self):
        """Handler parses message, tracks in-flight, and calls callback."""
        buf = RabbitMQBuffer()
        callback = AsyncMock()
        handler = buf._make_message_handler("ch1", callback)

        amqp_msg = _mock_amqp_message()
        await handler(amqp_msg)

        callback.assert_awaited_once()
        assert "msg-001" in buf._in_flight

    @pytest.mark.asyncio
    async def test_handler_callback_failure_requeues(self):
        """Handler requeues message on callback failure under limit."""
        buf = RabbitMQBuffer(max_redelivery_attempts=5, requeue_delay_seconds=0.01)
        callback = AsyncMock(side_effect=Exception("delivery failed"))
        handler = buf._make_message_handler("ch1", callback)

        amqp_msg = _mock_amqp_message()
        await handler(amqp_msg)

        amqp_msg.reject.assert_awaited_once_with(requeue=True)
        assert "msg-001" not in buf._in_flight

    @pytest.mark.asyncio
    async def test_handler_callback_failure_max_retries_rejects(self):
        """Handler rejects without requeue when max retries exceeded."""
        buf = RabbitMQBuffer(max_redelivery_attempts=2, requeue_delay_seconds=0.01)
        buf._stats["ch1"] = {"dead_lettered": 0, "delivered": 0, "expired": 0}
        callback = AsyncMock(side_effect=Exception("delivery failed"))
        handler = buf._make_message_handler("ch1", callback)

        amqp_msg = _mock_amqp_message()
        # Pre-set requeue count to max - 1
        buf._requeue_counts[amqp_msg.message_id] = 1

        await handler(amqp_msg)

        amqp_msg.reject.assert_awaited_once_with(requeue=False)
        assert buf._stats["ch1"]["dead_lettered"] == 1

    @pytest.mark.asyncio
    async def test_handler_parse_failure(self):
        """Handler handles unparseable message body gracefully."""
        buf = RabbitMQBuffer(max_redelivery_attempts=5, requeue_delay_seconds=0.01)
        callback = AsyncMock()
        handler = buf._make_message_handler("ch1", callback)

        amqp_msg = _mock_amqp_message(body=b"not-json{{{")
        await handler(amqp_msg)

        callback.assert_not_awaited()
        amqp_msg.reject.assert_awaited_once_with(requeue=True)


# ─── subscribe / subscribe_webhook / _start_webhook_consumer ─────────────────

class TestRabbitMQBufferSubscribe:
    """Tests for subscribe() and related methods."""

    @pytest.mark.asyncio
    async def test_subscribe_not_connected_raises(self):
        """subscribe raises ConnectionError when not connected."""
        buf = RabbitMQBuffer()
        with pytest.raises(ConnectionError, match="Not connected"):
            await buf.subscribe("ch1", AsyncMock())

    @pytest.mark.asyncio
    async def test_subscribe_with_webhook_ids(self):
        """subscribe starts consumers for each webhook_id."""
        buf = RabbitMQBuffer()
        buf.channel = _mock_channel()
        callback = AsyncMock()

        tag = await buf.subscribe("ch1", callback, webhook_ids=["wh1", "wh2"])
        assert tag == "channel_sub:ch1"
        assert callback is buf._channel_callbacks["ch1"]
        assert "ch1" in buf._channel_consumers

    @pytest.mark.asyncio
    async def test_subscribe_no_webhook_ids(self):
        """subscribe with no webhook_ids returns composite tag."""
        buf = RabbitMQBuffer()
        buf.channel = _mock_channel()
        callback = AsyncMock()

        tag = await buf.subscribe("ch1", callback)
        assert tag == "channel_sub:ch1"

    @pytest.mark.asyncio
    async def test_start_webhook_consumer_not_connected(self):
        """_start_webhook_consumer returns None when not connected."""
        buf = RabbitMQBuffer()
        result = await buf._start_webhook_consumer("ch1", "wh1", AsyncMock())
        assert result is None

    @pytest.mark.asyncio
    async def test_start_webhook_consumer_queue_not_found(self):
        """_start_webhook_consumer returns None when queue doesn't exist."""
        buf = RabbitMQBuffer()
        buf.channel = _mock_channel()
        buf.channel.declare_queue.side_effect = Exception("NOT_FOUND")

        result = await buf._start_webhook_consumer("ch1", "wh1", AsyncMock())
        assert result is None

    @pytest.mark.asyncio
    async def test_start_webhook_consumer_success(self):
        """_start_webhook_consumer starts consuming and tracks consumer."""
        buf = RabbitMQBuffer()
        buf.channel = _mock_channel()
        mock_q = _mock_queue(consume_tag="wh1-tag")
        buf.channel.declare_queue.return_value = mock_q
        buf._channel_consumers["ch1"] = {}

        tag = await buf._start_webhook_consumer("ch1", "wh1", AsyncMock())
        assert tag == "wh1-tag"
        assert buf._channel_consumers["ch1"]["wh1"] == "wh1-tag"
        assert "wh1-tag" in buf._consumer_queues

    @pytest.mark.asyncio
    async def test_subscribe_webhook_no_callback_stored(self):
        """subscribe_webhook returns None when no callback stored."""
        buf = RabbitMQBuffer()
        result = await buf.subscribe_webhook("ch1", "wh1")
        assert result is None

    @pytest.mark.asyncio
    async def test_subscribe_webhook_already_consuming(self):
        """subscribe_webhook returns existing tag for duplicate webhook."""
        buf = RabbitMQBuffer()
        buf._channel_callbacks["ch1"] = AsyncMock()
        buf._channel_consumers["ch1"] = {"wh1": "existing-tag"}

        tag = await buf.subscribe_webhook("ch1", "wh1")
        assert tag == "existing-tag"

    @pytest.mark.asyncio
    async def test_subscribe_webhook_new_webhook(self):
        """subscribe_webhook starts consumer for new webhook."""
        buf = RabbitMQBuffer()
        buf.channel = _mock_channel()
        mock_q = _mock_queue(consume_tag="new-tag")
        buf.channel.declare_queue.return_value = mock_q
        buf._channel_callbacks["ch1"] = AsyncMock()
        buf._channel_consumers["ch1"] = {}

        tag = await buf.subscribe_webhook("ch1", "wh2")
        assert tag == "new-tag"

    @pytest.mark.asyncio
    async def test_subscribe_webhook_with_explicit_callback(self):
        """subscribe_webhook uses provided callback over stored one."""
        buf = RabbitMQBuffer()
        buf.channel = _mock_channel()
        mock_q = _mock_queue(consume_tag="cb-tag")
        buf.channel.declare_queue.return_value = mock_q
        buf._channel_consumers["ch1"] = {}

        explicit_cb = AsyncMock()
        tag = await buf.subscribe_webhook("ch1", "wh3", callback=explicit_cb)
        assert tag == "cb-tag"


# ─── unsubscribe ─────────────────────────────────────────────────────────────

class TestRabbitMQBufferUnsubscribe:
    """Tests for unsubscribe()."""

    @pytest.mark.asyncio
    async def test_unsubscribe_not_connected(self):
        """unsubscribe is a no-op when not connected."""
        buf = RabbitMQBuffer()
        buf.channel = None
        await buf.unsubscribe("channel_sub:ch1")

    @pytest.mark.asyncio
    async def test_unsubscribe_composite_tag(self):
        """unsubscribe with composite tag cancels all per-webhook consumers."""
        buf = RabbitMQBuffer()
        buf.channel = _mock_channel()

        mock_q = _mock_queue()
        buf._channel_consumers["ch1"] = {"wh1": "tag-1", "wh2": "tag-2"}
        buf._channel_callbacks["ch1"] = AsyncMock()
        buf._consumer_queues["tag-1"] = mock_q
        buf._consumer_queues["tag-2"] = mock_q

        await buf.unsubscribe("channel_sub:ch1")

        assert "ch1" not in buf._channel_consumers
        assert "ch1" not in buf._channel_callbacks
        assert mock_q.cancel.await_count == 2

    @pytest.mark.asyncio
    async def test_unsubscribe_composite_tag_no_queue_ref(self):
        """unsubscribe handles missing queue reference gracefully."""
        buf = RabbitMQBuffer()
        buf.channel = _mock_channel()
        buf._channel_consumers["ch1"] = {"wh1": "tag-1"}
        buf._channel_callbacks["ch1"] = AsyncMock()
        # No queue reference in _consumer_queues

        await buf.unsubscribe("channel_sub:ch1")
        # Should not raise

    @pytest.mark.asyncio
    async def test_unsubscribe_composite_tag_cancel_error(self):
        """unsubscribe handles cancel errors gracefully."""
        buf = RabbitMQBuffer()
        buf.channel = _mock_channel()

        mock_q = _mock_queue()
        mock_q.cancel.side_effect = Exception("cancel failed")
        buf._channel_consumers["ch1"] = {"wh1": "tag-1"}
        buf._channel_callbacks["ch1"] = AsyncMock()
        buf._consumer_queues["tag-1"] = mock_q

        await buf.unsubscribe("channel_sub:ch1")
        # Should not raise

    @pytest.mark.asyncio
    async def test_unsubscribe_single_tag(self):
        """unsubscribe with single tag cancels specific consumer."""
        buf = RabbitMQBuffer()
        buf.channel = _mock_channel()

        mock_q = _mock_queue()
        buf._consumer_queues["tag-1"] = mock_q

        await buf.unsubscribe("tag-1")
        mock_q.cancel.assert_awaited_once_with("tag-1")

    @pytest.mark.asyncio
    async def test_unsubscribe_single_tag_no_queue_ref(self):
        """unsubscribe with single tag and no queue ref logs warning."""
        buf = RabbitMQBuffer()
        buf.channel = _mock_channel()

        await buf.unsubscribe("unknown-tag")
        # Should not raise

    @pytest.mark.asyncio
    async def test_unsubscribe_single_tag_cancel_error(self):
        """unsubscribe with single tag handles cancel error."""
        buf = RabbitMQBuffer()
        buf.channel = _mock_channel()

        mock_q = _mock_queue()
        mock_q.cancel.side_effect = Exception("cancel failed")
        buf._consumer_queues["tag-1"] = mock_q

        await buf.unsubscribe("tag-1")
        # Should not raise


# ─── ack / nack ──────────────────────────────────────────────────────────────

class TestRabbitMQBufferAckNack:
    """Tests for ack() and nack()."""

    @pytest.mark.asyncio
    async def test_ack_not_in_flight(self):
        """ack returns False when message not tracked."""
        buf = RabbitMQBuffer()
        result = await buf.ack("ch1", "msg-unknown")
        assert result is False

    @pytest.mark.asyncio
    async def test_ack_success(self):
        """ack acknowledges message and updates stats."""
        buf = RabbitMQBuffer()
        amqp_msg = _mock_amqp_message()
        buf._in_flight["msg-001"] = amqp_msg
        buf._stats["ch1"] = {"delivered": 0}
        buf._requeue_counts["msg-001"] = 3

        result = await buf.ack("ch1", "msg-001")
        assert result is True
        amqp_msg.ack.assert_awaited_once()
        assert buf._stats["ch1"]["delivered"] == 1
        assert "msg-001" not in buf._requeue_counts
        assert "msg-001" not in buf._in_flight

    @pytest.mark.asyncio
    async def test_ack_error(self):
        """ack returns False on AMQP error."""
        buf = RabbitMQBuffer()
        amqp_msg = _mock_amqp_message()
        amqp_msg.ack.side_effect = Exception("ack failed")
        buf._in_flight["msg-001"] = amqp_msg

        result = await buf.ack("ch1", "msg-001")
        assert result is False

    @pytest.mark.asyncio
    async def test_nack_not_in_flight(self):
        """nack returns False when message not tracked."""
        buf = RabbitMQBuffer()
        result = await buf.nack("ch1", "msg-unknown")
        assert result is False

    @pytest.mark.asyncio
    async def test_nack_retry_true(self):
        """nack with retry=True requeues message."""
        buf = RabbitMQBuffer()
        amqp_msg = _mock_amqp_message()
        buf._in_flight["msg-001"] = amqp_msg

        result = await buf.nack("ch1", "msg-001", retry=True)
        assert result is True
        amqp_msg.reject.assert_awaited_once_with(requeue=True)

    @pytest.mark.asyncio
    async def test_nack_retry_false(self):
        """nack with retry=False rejects without requeue (sends to DLX)."""
        buf = RabbitMQBuffer()
        buf._stats["ch1"] = {"dead_lettered": 0}
        amqp_msg = _mock_amqp_message()
        buf._in_flight["msg-001"] = amqp_msg

        result = await buf.nack("ch1", "msg-001", retry=False)
        assert result is True
        amqp_msg.reject.assert_awaited_once_with(requeue=False)
        assert buf._stats["ch1"]["dead_lettered"] == 1

    @pytest.mark.asyncio
    async def test_nack_error(self):
        """nack returns False on AMQP error."""
        buf = RabbitMQBuffer()
        amqp_msg = _mock_amqp_message()
        amqp_msg.reject.side_effect = Exception("reject failed")
        buf._in_flight["msg-001"] = amqp_msg

        result = await buf.nack("ch1", "msg-001", retry=True)
        assert result is False


# ─── get_queue_depth / get_in_flight_count / get_stats ───────────────────────

class TestRabbitMQBufferStats:
    """Tests for statistics methods."""

    @pytest.mark.asyncio
    async def test_get_queue_depth_not_connected(self):
        """get_queue_depth returns 0 when not connected."""
        buf = RabbitMQBuffer()
        buf.connection = None
        result = await buf.get_queue_depth("ch1")
        assert result == 0

    @pytest.mark.asyncio
    async def test_get_queue_depth_success(self):
        """get_queue_depth returns message count from queue."""
        buf = RabbitMQBuffer()
        buf.connection = _mock_connection()
        mock_ch = _mock_channel()
        mock_q = _mock_queue()
        mock_q.declaration_result.message_count = 15
        mock_ch.declare_queue.return_value = mock_q
        buf.connection.channel.return_value = mock_ch

        result = await buf.get_queue_depth("ch1", webhook_id="wh1")
        assert result == 15

    @pytest.mark.asyncio
    async def test_get_queue_depth_error(self):
        """get_queue_depth returns 0 on error."""
        buf = RabbitMQBuffer()
        buf.connection = _mock_connection()
        buf.connection.channel.side_effect = Exception("channel error")

        result = await buf.get_queue_depth("ch1")
        assert result == 0

    @pytest.mark.asyncio
    async def test_get_webhook_queue_depths(self):
        """get_webhook_queue_depths returns depth for each webhook."""
        buf = RabbitMQBuffer()
        buf.connection = _mock_connection()
        mock_ch = _mock_channel()
        mock_q = _mock_queue()
        mock_q.declaration_result.message_count = 7
        mock_ch.declare_queue.return_value = mock_q
        buf.connection.channel.return_value = mock_ch

        depths = await buf.get_webhook_queue_depths("ch1", ["wh1", "wh2"])
        assert depths == {"wh1": 7, "wh2": 7}

    @pytest.mark.asyncio
    async def test_get_in_flight_count(self):
        """get_in_flight_count returns count for specific channel."""
        buf = RabbitMQBuffer()
        msg1 = _mock_amqp_message("msg-1", headers={"channel": "ch1"})
        msg2 = _mock_amqp_message("msg-2", headers={"channel": "ch1"})
        msg3 = _mock_amqp_message("msg-3", headers={"channel": "ch2"})
        buf._in_flight = {"msg-1": msg1, "msg-2": msg2, "msg-3": msg3}

        result = await buf.get_in_flight_count("ch1")
        assert result == 2

    @pytest.mark.asyncio
    async def test_get_in_flight_count_no_headers(self):
        """get_in_flight_count handles messages with no headers."""
        buf = RabbitMQBuffer()
        msg = _mock_amqp_message("msg-1")
        msg.headers = None
        buf._in_flight = {"msg-1": msg}

        result = await buf.get_in_flight_count("ch1")
        assert result == 0

    @pytest.mark.asyncio
    async def test_get_stats(self):
        """get_stats returns ChannelStats with correct values."""
        buf = RabbitMQBuffer()
        buf.connection = _mock_connection()
        mock_ch = _mock_channel()
        mock_q = _mock_queue()
        mock_q.declaration_result.message_count = 20
        mock_ch.declare_queue.return_value = mock_q
        buf.connection.channel.return_value = mock_ch
        buf._stats["ch1"] = {"delivered": 100, "expired": 5, "dead_lettered": 3}

        stats = await buf.get_stats("ch1")
        assert isinstance(stats, ChannelStats)
        assert stats.messages_delivered == 100
        assert stats.messages_expired == 5
        assert stats.messages_dead_lettered == 3

    @pytest.mark.asyncio
    async def test_get_stats_no_stats(self):
        """get_stats returns zeros for unknown channel."""
        buf = RabbitMQBuffer()
        buf.connection = _mock_connection()
        mock_ch = _mock_channel()
        mock_q = _mock_queue()
        mock_q.declaration_result.message_count = 0
        mock_ch.declare_queue.return_value = mock_q
        buf.connection.channel.return_value = mock_ch

        stats = await buf.get_stats("unknown")
        assert stats.messages_delivered == 0


# ─── cleanup_expired ─────────────────────────────────────────────────────────

class TestRabbitMQBufferCleanupExpired:
    """Tests for cleanup_expired()."""

    @pytest.mark.asyncio
    async def test_cleanup_expired_returns_zero(self):
        """RabbitMQ handles TTL natively, cleanup_expired returns 0."""
        buf = RabbitMQBuffer()
        result = await buf.cleanup_expired("ch1")
        assert result == 0


# ─── delete_channel ──────────────────────────────────────────────────────────

class TestRabbitMQBufferDeleteChannel:
    """Tests for delete_channel()."""

    @pytest.mark.asyncio
    async def test_delete_channel_not_connected(self):
        """delete_channel returns False when not connected."""
        buf = RabbitMQBuffer()
        buf.channel = None
        result = await buf.delete_channel("ch1")
        assert result is False

    @pytest.mark.asyncio
    async def test_delete_channel_success(self):
        """delete_channel cleans up consumers and stats."""
        buf = RabbitMQBuffer()
        buf.channel = _mock_channel()
        buf._stats["ch1"] = {"delivered": 10}
        buf._channel_consumers["ch1"] = {"wh1": "tag-1"}
        buf._consumer_queues["tag-1"] = _mock_queue()
        buf._channel_callbacks["ch1"] = AsyncMock()

        result = await buf.delete_channel("ch1")
        assert result is True
        assert "ch1" not in buf._stats
        assert "ch1" not in buf._channel_consumers
        assert "ch1" not in buf._channel_callbacks

    @pytest.mark.asyncio
    async def test_delete_channel_with_webhook_ids(self):
        """delete_channel deletes per-webhook queues."""
        buf = RabbitMQBuffer()
        buf.channel = _mock_channel()
        buf._stats["ch1"] = {"delivered": 10}

        result = await buf.delete_channel("ch1", webhook_ids=["wh1", "wh2"])
        assert result is True
        # queue_delete called for each queue + DLQ (2 * 2 = 4)
        assert buf.channel.queue_delete.await_count == 4

    @pytest.mark.asyncio
    async def test_delete_channel_queue_delete_error(self):
        """delete_channel continues on per-queue delete errors."""
        buf = RabbitMQBuffer()
        buf.channel = _mock_channel()
        buf.channel.queue_delete.side_effect = Exception("queue error")
        buf._stats["ch1"] = {"delivered": 10}

        result = await buf.delete_channel("ch1", webhook_ids=["wh1"])
        assert result is True  # Errors are swallowed per-queue

    @pytest.mark.asyncio
    async def test_delete_channel_error(self):
        """delete_channel returns False on unexpected error."""
        buf = RabbitMQBuffer()
        buf.channel = _mock_channel()
        # Make _stats.pop raise to trigger outer except
        buf._stats = MagicMock()
        buf._stats.pop.side_effect = Exception("unexpected")
        buf._channel_consumers = MagicMock()
        buf._channel_consumers.pop.side_effect = Exception("unexpected")

        result = await buf.delete_channel("ch1")
        assert result is False


# ─── get_dead_letters ────────────────────────────────────────────────────────

class TestRabbitMQBufferGetDeadLetters:
    """Tests for get_dead_letters()."""

    @pytest.mark.asyncio
    async def test_get_dead_letters_not_connected(self):
        """get_dead_letters returns empty list when not connected."""
        buf = RabbitMQBuffer()
        buf.channel = None
        result = await buf.get_dead_letters("ch1")
        assert result == []

    @pytest.mark.asyncio
    async def test_get_dead_letters_no_queue(self):
        """get_dead_letters returns empty list when DLQ doesn't exist."""
        buf = RabbitMQBuffer()
        buf.channel = _mock_channel()
        buf.channel.get_queue.return_value = None

        result = await buf.get_dead_letters("ch1")
        assert result == []

    @pytest.mark.asyncio
    async def test_get_dead_letters_queue_error(self):
        """get_dead_letters returns empty list on queue error."""
        buf = RabbitMQBuffer()
        buf.channel = _mock_channel()
        buf.channel.get_queue.side_effect = Exception("queue error")

        result = await buf.get_dead_letters("ch1")
        assert result == []


# ─── health_check ────────────────────────────────────────────────────────────

class TestRabbitMQBufferHealthCheck:
    """Tests for health_check()."""

    @pytest.mark.asyncio
    async def test_health_check_healthy(self):
        """health_check returns True when connected."""
        buf = RabbitMQBuffer()
        buf.connection = _mock_connection(is_closed=False)
        result = await buf.health_check()
        assert result is True

    @pytest.mark.asyncio
    async def test_health_check_not_connected(self):
        """health_check returns False when not connected."""
        buf = RabbitMQBuffer()
        buf.connection = None
        result = await buf.health_check()
        assert result is False

    @pytest.mark.asyncio
    async def test_health_check_connection_closed(self):
        """health_check returns False when connection is closed."""
        buf = RabbitMQBuffer()
        buf.connection = _mock_connection(is_closed=True)
        result = await buf.health_check()
        assert result is False


# ─── Key naming helpers ──────────────────────────────────────────────────────

class TestRabbitMQBufferNaming:
    """Tests for naming helper methods."""

    @pytest.mark.asyncio
    async def test_queue_name_without_webhook_id(self):
        """_queue_name returns channel-level name."""
        buf = RabbitMQBuffer(exchange_name="wc")
        assert buf._queue_name("ch1") == "wc.ch1"

    @pytest.mark.asyncio
    async def test_queue_name_with_webhook_id(self):
        """_queue_name returns per-webhook name."""
        buf = RabbitMQBuffer(exchange_name="wc")
        assert buf._queue_name("ch1", "wh1") == "wc.ch1.wh1"

    @pytest.mark.asyncio
    async def test_dlq_name_without_webhook_id(self):
        """_dlq_name returns channel-level DLQ name."""
        buf = RabbitMQBuffer(exchange_name="wc")
        assert buf._dlq_name("ch1") == "wc.ch1.dlq"

    @pytest.mark.asyncio
    async def test_dlq_name_with_webhook_id(self):
        """_dlq_name returns per-webhook DLQ name."""
        buf = RabbitMQBuffer(exchange_name="wc")
        assert buf._dlq_name("ch1", "wh1") == "wc.ch1.wh1.dlq"

    @pytest.mark.asyncio
    async def test_routing_key_default(self):
        """_routing_key returns wildcard routing key."""
        buf = RabbitMQBuffer()
        assert buf._routing_key("ch1") == "ch1.*"

    @pytest.mark.asyncio
    async def test_routing_key_specific(self):
        """_routing_key returns specific routing key."""
        buf = RabbitMQBuffer()
        assert buf._routing_key("ch1", "wh1") == "ch1.wh1"
