"""
Unit tests for RedisBuffer (buffer/redis_buffer.py).

Covers missed lines including:
- connect / close lifecycle
- ensure_channel with and without webhook_id
- push success and failure paths
- subscribe and consume loop with stream discovery
- _process_stream_entry: happy path, expired messages, callback failures,
  redelivery exhaustion, DLQ, outer parse errors
- _retry_delivery: successful retry, exhausted retries, cancellation
- unsubscribe
- _move_to_dlq success and failure
- ack / nack (retry=True / retry=False with xrange results)
- get_queue_depth / get_in_flight_count / get_stats
- cleanup_expired
- delete_channel
- get_dead_letters (various parsing paths)
- health_check
"""

import asyncio
import json
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

from src.webhook_connect.buffer.redis_buffer import RedisBuffer
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


def _mock_redis():
    """Create a mock redis.asyncio.Redis instance."""
    r = AsyncMock()
    r.ping = AsyncMock()
    r.aclose = AsyncMock()
    r.xgroup_create = AsyncMock()
    r.hset = AsyncMock()
    r.xadd = AsyncMock(return_value=b"1234-0")
    r.xreadgroup = AsyncMock(return_value=[])
    r.xack = AsyncMock()
    r.xdel = AsyncMock()
    r.xinfo_stream = AsyncMock(return_value={"length": 42})
    r.xrange = AsyncMock(return_value=[])
    r.xtrim = AsyncMock(return_value=0)
    r.zadd = AsyncMock()
    r.zrevrange = AsyncMock(return_value=[])
    r.hgetall = AsyncMock(return_value={})
    r.delete = AsyncMock()

    # scan_iter returns async iterator
    async def _scan_iter(**kwargs):
        return
        yield  # makes this an async generator

    r.scan_iter = _scan_iter
    return r


# ─── Connect / Close ─────────────────────────────────────────────────────────

class TestRedisBufferConnectClose:
    """Tests for connect() and close() lifecycle."""

    @pytest.mark.asyncio
    async def test_connect_success(self):
        """Successful connect sets redis attribute and pings."""
        buf = RedisBuffer(url="redis://localhost:6379/0")
        mock_r = _mock_redis()
        with patch("src.webhook_connect.buffer.redis_buffer.redis.from_url", return_value=mock_r):
            await buf.connect()
        assert buf.redis is mock_r
        mock_r.ping.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_connect_failure_raises(self):
        """connect() raises ConnectionError when ping fails."""
        buf = RedisBuffer()
        mock_r = _mock_redis()
        mock_r.ping.side_effect = Exception("refused")
        with patch("src.webhook_connect.buffer.redis_buffer.redis.from_url", return_value=mock_r):
            with pytest.raises(ConnectionError, match="Failed to connect"):
                await buf.connect()

    @pytest.mark.asyncio
    async def test_close_cancels_consumer_tasks(self):
        """close() cancels consumer tasks and clears them."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()

        # Add a fake consumer task
        task = asyncio.create_task(asyncio.sleep(100))
        buf._consumer_tasks["tag1"] = task

        await buf.close()
        assert task.cancelled()
        assert len(buf._consumer_tasks) == 0
        assert buf.redis is None

    @pytest.mark.asyncio
    async def test_close_cancels_retry_tasks(self):
        """close() cancels pending retry tasks."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()

        task = asyncio.create_task(asyncio.sleep(100))
        buf._retry_tasks.add(task)

        await buf.close()
        assert task.cancelled()
        assert len(buf._retry_tasks) == 0

    @pytest.mark.asyncio
    async def test_close_when_no_redis(self):
        """close() is safe to call when redis is None."""
        buf = RedisBuffer()
        buf.redis = None
        await buf.close()  # Should not raise


# ─── ensure_channel ──────────────────────────────────────────────────────────

class TestRedisBufferEnsureChannel:
    """Tests for ensure_channel()."""

    @pytest.mark.asyncio
    async def test_ensure_channel_not_connected_raises(self):
        """ensure_channel raises ConnectionError when not connected."""
        buf = RedisBuffer()
        with pytest.raises(ConnectionError, match="Not connected"):
            await buf.ensure_channel("ch1")

    @pytest.mark.asyncio
    async def test_ensure_channel_creates_group(self):
        """ensure_channel creates consumer group and writes metadata."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        await buf.ensure_channel("ch1", ttl_seconds=3600)
        buf.redis.xgroup_create.assert_awaited_once()
        buf.redis.hset.assert_awaited_once()
        assert "ch1" in buf._stats

    @pytest.mark.asyncio
    async def test_ensure_channel_group_already_exists(self):
        """ensure_channel handles BUSYGROUP error gracefully."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        import redis as sync_redis
        buf.redis.xgroup_create.side_effect = sync_redis.ResponseError("BUSYGROUP Consumer Group name already exists")
        await buf.ensure_channel("ch1")
        # Should not raise

    @pytest.mark.asyncio
    async def test_ensure_channel_with_webhook_id(self):
        """ensure_channel with webhook_id uses per-webhook stream key."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        await buf.ensure_channel("ch1", webhook_id="wh1")
        call_args = buf.redis.xgroup_create.call_args
        stream_key = call_args[0][0]
        assert "wh1" in stream_key

    @pytest.mark.asyncio
    async def test_ensure_channel_propagates_non_busygroup_error(self):
        """ensure_channel re-raises non-BUSYGROUP ResponseError."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        import redis as sync_redis
        buf.redis.xgroup_create.side_effect = sync_redis.ResponseError("Something else")
        with pytest.raises(sync_redis.ResponseError, match="Something else"):
            await buf.ensure_channel("ch1")


# ─── push ────────────────────────────────────────────────────────────────────

class TestRedisBufferPush:
    """Tests for push()."""

    @pytest.mark.asyncio
    async def test_push_not_connected_raises(self):
        """push raises ConnectionError when not connected."""
        buf = RedisBuffer()
        with pytest.raises(ConnectionError, match="Not connected"):
            await buf.push("ch1", _make_message())

    @pytest.mark.asyncio
    async def test_push_success(self):
        """push adds message to stream and returns True."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        msg = _make_message()
        result = await buf.push("ch1", msg)
        assert result is True
        buf.redis.xadd.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_push_failure_returns_false(self):
        """push returns False when xadd raises."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        buf.redis.xadd.side_effect = Exception("redis error")
        result = await buf.push("ch1", _make_message())
        assert result is False

    @pytest.mark.asyncio
    async def test_push_message_without_expires_at(self):
        """push handles message with no expires_at."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        msg = _make_message(expires_at=None)
        result = await buf.push("ch1", msg)
        assert result is True

    @pytest.mark.asyncio
    async def test_push_message_with_expires_at(self):
        """push includes expires_at when set."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        msg = _make_message(expires_at=future)
        result = await buf.push("ch1", msg)
        assert result is True
        call_args = buf.redis.xadd.call_args
        data_dict = call_args[0][1]
        assert data_dict["expires_at"] != ""


# ─── subscribe / _consume_loop / _discover_streams ───────────────────────────

class TestRedisBufferSubscribe:
    """Tests for subscribe() and the internal consume loop."""

    @pytest.mark.asyncio
    async def test_subscribe_not_connected_raises(self):
        """subscribe raises ConnectionError when not connected."""
        buf = RedisBuffer()
        with pytest.raises(ConnectionError, match="Not connected"):
            await buf.subscribe("ch1", AsyncMock())

    @pytest.mark.asyncio
    async def test_subscribe_returns_consumer_tag(self):
        """subscribe returns a consumer tag and creates a background task."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        tag = await buf.subscribe("ch1", AsyncMock())
        assert tag is not None
        assert tag in buf._consumer_tasks
        # Cleanup
        await buf.close()

    @pytest.mark.asyncio
    async def test_discover_streams_not_connected(self):
        """_discover_streams returns empty list when not connected."""
        buf = RedisBuffer()
        buf.redis = None
        result = await buf._discover_streams("ch1")
        assert result == []

    @pytest.mark.asyncio
    async def test_discover_streams_decodes_bytes(self):
        """_discover_streams decodes byte keys from SCAN."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()

        async def _scan_iter(**kwargs):
            yield b"prefix:stream:ch1:wh1"
            yield b"prefix:stream:ch1:wh2"

        buf.redis.scan_iter = _scan_iter
        result = await buf._discover_streams("ch1")
        assert len(result) == 2
        assert all(isinstance(k, str) for k in result)


# ─── _process_stream_entry ───────────────────────────────────────────────────

class TestRedisBufferProcessStreamEntry:
    """Tests for _process_stream_entry()."""

    @pytest.mark.asyncio
    async def test_process_entry_happy_path(self):
        """Successful callback clears in_flight and returns."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        msg = _make_message()
        envelope = msg.to_envelope()
        data = {
            b"message_id": b"msg-001",
            b"data": json.dumps(envelope).encode(),
        }
        callback = AsyncMock()

        await buf._process_stream_entry("ch1", b"stream:ch1:wh1", b"1-0", data, "grp", callback)
        callback.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_process_entry_expired_message(self):
        """Expired messages are acked and skipped."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        buf._stats["ch1"] = {"expired": 0, "delivered": 0, "dead_lettered": 0}

        past = datetime.now(timezone.utc) - timedelta(hours=1)
        msg = _make_message(expires_at=past)
        envelope = msg.to_envelope()
        data = {
            b"message_id": b"msg-001",
            b"data": json.dumps(envelope).encode(),
        }
        callback = AsyncMock()

        await buf._process_stream_entry("ch1", b"stream:ch1:wh1", b"1-0", data, "grp", callback)
        callback.assert_not_awaited()
        buf.redis.xack.assert_awaited_once()
        assert buf._stats["ch1"]["expired"] == 1

    @pytest.mark.asyncio
    async def test_process_entry_callback_failure_spawns_retry(self):
        """When callback fails, a retry task is spawned."""
        buf = RedisBuffer(max_redelivery_attempts=5, requeue_delay_seconds=0.01)
        buf.redis = _mock_redis()
        buf._stats["ch1"] = {"expired": 0, "delivered": 0, "dead_lettered": 0}

        msg = _make_message()
        envelope = msg.to_envelope()
        data = {
            b"message_id": b"msg-001",
            b"data": json.dumps(envelope).encode(),
        }
        callback = AsyncMock(side_effect=Exception("delivery failed"))

        await buf._process_stream_entry("ch1", b"stream:ch1:wh1", b"1-0", data, "grp", callback)

        # A retry task should have been spawned
        assert len(buf._retry_tasks) >= 1
        # Cleanup
        for t in list(buf._retry_tasks):
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass

    @pytest.mark.asyncio
    async def test_process_entry_callback_failure_max_retries_dlq(self):
        """When callback fails and max retries reached, message goes to DLQ."""
        buf = RedisBuffer(max_redelivery_attempts=2, requeue_delay_seconds=0.01)
        buf.redis = _mock_redis()
        buf._stats["ch1"] = {"expired": 0, "delivered": 0, "dead_lettered": 0}

        msg = _make_message()
        envelope = msg.to_envelope()
        data = {
            b"message_id": b"msg-001",
            b"data": json.dumps(envelope).encode(),
        }
        callback = AsyncMock(side_effect=Exception("delivery failed"))

        # Pre-set requeue count to be at max
        buf._requeue_counts["msg-001"] = 1

        await buf._process_stream_entry("ch1", b"stream:ch1:wh1", b"1-0", data, "grp", callback)

        # Should have moved to DLQ
        buf.redis.zadd.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_process_entry_parse_error_outer(self):
        """Outer exception (bad JSON) increments requeue count."""
        buf = RedisBuffer(max_redelivery_attempts=3, requeue_delay_seconds=0.01)
        buf.redis = _mock_redis()

        data = {
            b"message_id": b"msg-bad",
            b"data": b"not-json{{{",
        }
        callback = AsyncMock()

        await buf._process_stream_entry("ch1", b"stream:ch1:wh1", b"1-0", data, "grp", callback)
        callback.assert_not_awaited()
        assert buf._requeue_counts.get("msg-bad", 0) >= 1

    @pytest.mark.asyncio
    async def test_process_entry_parse_error_hits_dlq(self):
        """Outer parse error at max retries sends to DLQ."""
        buf = RedisBuffer(max_redelivery_attempts=2, requeue_delay_seconds=0.01)
        buf.redis = _mock_redis()

        data = {
            b"message_id": b"msg-bad",
            b"data": b"not-json{{{",
        }
        # Pre-set requeue count to max - 1
        buf._requeue_counts["msg-bad"] = 1
        callback = AsyncMock()

        await buf._process_stream_entry("ch1", b"stream:ch1:wh1", b"1-0", data, "grp", callback)
        buf.redis.zadd.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_process_entry_with_string_keys(self):
        """_process_stream_entry handles string keys in data dict."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        msg = _make_message()
        envelope = msg.to_envelope()
        data = {
            "message_id": "msg-001",
            "data": json.dumps(envelope),
        }
        callback = AsyncMock()

        await buf._process_stream_entry("ch1", "stream:ch1:wh1", "1-0", data, "grp", callback)
        callback.assert_awaited_once()


# ─── _retry_delivery ─────────────────────────────────────────────────────────

class TestRedisBufferRetryDelivery:
    """Tests for _retry_delivery()."""

    @pytest.mark.asyncio
    async def test_retry_delivery_success_on_second_attempt(self):
        """Retry succeeds on second attempt, cleans up requeue counts."""
        buf = RedisBuffer(max_redelivery_attempts=5, requeue_delay_seconds=0.01)
        buf.redis = _mock_redis()
        msg = _make_message()

        call_count = 0
        async def callback(m):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("first attempt fails")
            # second attempt succeeds

        buf._requeue_counts["msg-001"] = 1

        await buf._retry_delivery(
            msg, "ch1", "1-0", {}, "stream:ch1:wh1", callback, attempt=1
        )
        assert call_count == 2
        assert "msg-001" not in buf._requeue_counts

    @pytest.mark.asyncio
    async def test_retry_delivery_exhausted_goes_to_dlq(self):
        """All retries exhausted sends message to DLQ."""
        buf = RedisBuffer(max_redelivery_attempts=2, requeue_delay_seconds=0.01)
        buf.redis = _mock_redis()
        msg = _make_message()
        callback = AsyncMock(side_effect=Exception("always fails"))

        await buf._retry_delivery(
            msg, "ch1", "1-0", {}, "stream:ch1:wh1", callback, attempt=1
        )
        buf.redis.zadd.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_retry_delivery_cancelled(self):
        """Cancellation cleans up in-flight and requeue counts."""
        buf = RedisBuffer(max_redelivery_attempts=100, requeue_delay_seconds=100)
        buf.redis = _mock_redis()
        msg = _make_message()
        buf._requeue_counts["msg-001"] = 1
        callback = AsyncMock(side_effect=Exception("fails"))

        task = asyncio.create_task(
            buf._retry_delivery(
                msg, "ch1", "1-0", {}, "stream:ch1:wh1", callback, attempt=1
            )
        )
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        assert "msg-001" not in buf._requeue_counts


# ─── unsubscribe ─────────────────────────────────────────────────────────────

class TestRedisBufferUnsubscribe:
    """Tests for unsubscribe()."""

    @pytest.mark.asyncio
    async def test_unsubscribe_existing_task(self):
        """unsubscribe cancels a running consumer task."""
        buf = RedisBuffer()
        task = asyncio.create_task(asyncio.sleep(100))
        buf._consumer_tasks["tag-x"] = task
        await buf.unsubscribe("tag-x")
        assert task.cancelled()
        assert "tag-x" not in buf._consumer_tasks

    @pytest.mark.asyncio
    async def test_unsubscribe_nonexistent_tag(self):
        """unsubscribe with unknown tag is a no-op."""
        buf = RedisBuffer()
        await buf.unsubscribe("does-not-exist")
        # Should not raise


# ─── _move_to_dlq ───────────────────────────────────────────────────────────

class TestRedisBufferMoveToDlq:
    """Tests for _move_to_dlq()."""

    @pytest.mark.asyncio
    async def test_move_to_dlq_success(self):
        """_move_to_dlq adds to sorted set and acks original."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        buf._stats["ch1"] = {"dead_lettered": 0}

        data = {b"message_id": b"msg-001", b"data": b"{}"}
        await buf._move_to_dlq("ch1", "1-0", data, "some error", stream_key="stream:ch1:wh1")
        buf.redis.zadd.assert_awaited_once()
        buf.redis.xack.assert_awaited_once()
        assert buf._stats["ch1"]["dead_lettered"] == 1

    @pytest.mark.asyncio
    async def test_move_to_dlq_without_stream_key(self):
        """_move_to_dlq uses default stream key when none provided."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        buf._stats["ch1"] = {"dead_lettered": 0}

        data = {"message_id": "msg-001", "data": "{}"}
        await buf._move_to_dlq("ch1", "1-0", data, "error")
        buf.redis.xack.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_move_to_dlq_error_handling(self):
        """_move_to_dlq handles Redis errors gracefully."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        buf.redis.zadd.side_effect = Exception("redis down")

        data = {b"message_id": b"msg-001"}
        # Should not raise
        await buf._move_to_dlq("ch1", "1-0", data, "error")

    @pytest.mark.asyncio
    async def test_move_to_dlq_channel_not_in_stats(self):
        """_move_to_dlq handles missing stats gracefully."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()

        data = {b"message_id": b"msg-001"}
        await buf._move_to_dlq("unknown_ch", "1-0", data, "error")
        buf.redis.zadd.assert_awaited_once()


# ─── ack / nack ──────────────────────────────────────────────────────────────

class TestRedisBufferAckNack:
    """Tests for ack() and nack()."""

    @pytest.mark.asyncio
    async def test_ack_not_connected(self):
        """ack returns False when not connected."""
        buf = RedisBuffer()
        buf.redis = None
        result = await buf.ack("ch1", "msg-001")
        assert result is False

    @pytest.mark.asyncio
    async def test_ack_message_not_in_flight(self):
        """ack returns False when message not tracked."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        result = await buf.ack("ch1", "msg-unknown")
        assert result is False

    @pytest.mark.asyncio
    async def test_ack_success(self):
        """ack acknowledges and deletes stream entry."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        buf._in_flight["msg-001"] = {"stream_id": "1-0", "channel": "ch1", "stream_key": "stream:ch1:wh1"}
        buf._stats["ch1"] = {"delivered": 0}
        buf._requeue_counts["msg-001"] = 3

        result = await buf.ack("ch1", "msg-001")
        assert result is True
        buf.redis.xack.assert_awaited_once()
        buf.redis.xdel.assert_awaited_once()
        assert buf._stats["ch1"]["delivered"] == 1
        assert "msg-001" not in buf._requeue_counts

    @pytest.mark.asyncio
    async def test_ack_redis_error(self):
        """ack returns False on Redis error."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        buf._in_flight["msg-001"] = {"stream_id": "1-0", "channel": "ch1", "stream_key": "stream:ch1:wh1"}
        buf.redis.xack.side_effect = Exception("redis error")

        result = await buf.ack("ch1", "msg-001")
        assert result is False

    @pytest.mark.asyncio
    async def test_ack_uses_default_stream_key(self):
        """ack uses default stream key when not in info dict."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        buf._in_flight["msg-001"] = {"stream_id": "1-0", "channel": "ch1"}
        buf._stats["ch1"] = {"delivered": 0}

        result = await buf.ack("ch1", "msg-001")
        assert result is True

    @pytest.mark.asyncio
    async def test_nack_not_connected(self):
        """nack returns False when not connected."""
        buf = RedisBuffer()
        buf.redis = None
        result = await buf.nack("ch1", "msg-001")
        assert result is False

    @pytest.mark.asyncio
    async def test_nack_message_not_in_flight(self):
        """nack returns False when message not tracked."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        result = await buf.nack("ch1", "msg-unknown")
        assert result is False

    @pytest.mark.asyncio
    async def test_nack_retry_true(self):
        """nack with retry=True redelivers the message."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        buf._in_flight["msg-001"] = {"stream_id": "1-0", "channel": "ch1", "stream_key": "stream:ch1:wh1"}

        result = await buf.nack("ch1", "msg-001", retry=True)
        assert result is True

    @pytest.mark.asyncio
    async def test_nack_retry_false_with_messages(self):
        """nack with retry=False and existing messages moves to DLQ."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        buf._in_flight["msg-001"] = {"stream_id": "1-0", "channel": "ch1", "stream_key": "stream:ch1:wh1"}
        buf.redis.xrange.return_value = [("1-0", {b"data": b"{}"})]

        result = await buf.nack("ch1", "msg-001", retry=False)
        assert result is True
        buf.redis.zadd.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_nack_retry_false_no_messages(self):
        """nack with retry=False and no messages just acks."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        buf._in_flight["msg-001"] = {"stream_id": "1-0", "channel": "ch1", "stream_key": "stream:ch1:wh1"}
        buf.redis.xrange.return_value = []

        result = await buf.nack("ch1", "msg-001", retry=False)
        assert result is True
        buf.redis.xack.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_nack_redis_error(self):
        """nack returns False on Redis error."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        buf._in_flight["msg-001"] = {"stream_id": "1-0", "channel": "ch1", "stream_key": "stream:ch1:wh1"}
        buf.redis.xrange.side_effect = Exception("redis error")

        result = await buf.nack("ch1", "msg-001", retry=False)
        assert result is False


# ─── get_queue_depth / get_in_flight_count / get_stats ───────────────────────

class TestRedisBufferStats:
    """Tests for statistics and depth methods."""

    @pytest.mark.asyncio
    async def test_get_queue_depth_not_connected(self):
        """get_queue_depth returns 0 when not connected."""
        buf = RedisBuffer()
        buf.redis = None
        result = await buf.get_queue_depth("ch1")
        assert result == 0

    @pytest.mark.asyncio
    async def test_get_queue_depth_success(self):
        """get_queue_depth returns stream length."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        result = await buf.get_queue_depth("ch1")
        assert result == 42

    @pytest.mark.asyncio
    async def test_get_queue_depth_with_webhook_id(self):
        """get_queue_depth uses per-webhook stream key."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        result = await buf.get_queue_depth("ch1", webhook_id="wh1")
        assert result == 42

    @pytest.mark.asyncio
    async def test_get_queue_depth_error_returns_zero(self):
        """get_queue_depth returns 0 on error."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        buf.redis.xinfo_stream.side_effect = Exception("stream not found")
        result = await buf.get_queue_depth("ch1")
        assert result == 0

    @pytest.mark.asyncio
    async def test_get_in_flight_count(self):
        """get_in_flight_count returns count for specific channel."""
        buf = RedisBuffer()
        buf._in_flight = {
            "msg-1": {"channel": "ch1"},
            "msg-2": {"channel": "ch1"},
            "msg-3": {"channel": "ch2"},
        }
        result = await buf.get_in_flight_count("ch1")
        assert result == 2

    @pytest.mark.asyncio
    async def test_get_in_flight_count_empty(self):
        """get_in_flight_count returns 0 when no messages."""
        buf = RedisBuffer()
        result = await buf.get_in_flight_count("ch1")
        assert result == 0

    @pytest.mark.asyncio
    async def test_get_stats(self):
        """get_stats returns ChannelStats with correct values."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        buf._stats["ch1"] = {"delivered": 10, "expired": 2, "dead_lettered": 1}
        buf._in_flight = {"msg-1": {"channel": "ch1"}}

        stats = await buf.get_stats("ch1")
        assert isinstance(stats, ChannelStats)
        assert stats.channel == "ch1"
        assert stats.messages_delivered == 10
        assert stats.messages_expired == 2
        assert stats.messages_dead_lettered == 1
        assert stats.messages_in_flight == 1
        assert stats.messages_queued == 42

    @pytest.mark.asyncio
    async def test_get_stats_no_stats(self):
        """get_stats returns zeros for channel with no stats."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        stats = await buf.get_stats("unknown")
        assert stats.messages_delivered == 0

    @pytest.mark.asyncio
    async def test_get_webhook_queue_depths(self):
        """get_webhook_queue_depths returns depth for each webhook."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        depths = await buf.get_webhook_queue_depths("ch1", ["wh1", "wh2"])
        assert depths == {"wh1": 42, "wh2": 42}


# ─── cleanup_expired ─────────────────────────────────────────────────────────

class TestRedisBufferCleanupExpired:
    """Tests for cleanup_expired()."""

    @pytest.mark.asyncio
    async def test_cleanup_expired_not_connected(self):
        """cleanup_expired returns 0 when not connected."""
        buf = RedisBuffer()
        buf.redis = None
        result = await buf.cleanup_expired("ch1")
        assert result == 0

    @pytest.mark.asyncio
    async def test_cleanup_expired_trims_streams(self):
        """cleanup_expired trims old entries from discovered streams."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()

        async def _scan_iter(**kwargs):
            yield b"prefix:stream:ch1:wh1"

        buf.redis.scan_iter = _scan_iter
        buf.redis.hgetall.return_value = {b"ttl_seconds": b"3600"}
        buf.redis.xtrim.return_value = 5

        result = await buf.cleanup_expired("ch1")
        assert result == 5

    @pytest.mark.asyncio
    async def test_cleanup_expired_no_meta(self):
        """cleanup_expired skips streams with no metadata."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()

        async def _scan_iter(**kwargs):
            yield b"prefix:stream:ch1:wh1"

        buf.redis.scan_iter = _scan_iter
        buf.redis.hgetall.return_value = {}

        result = await buf.cleanup_expired("ch1")
        assert result == 0

    @pytest.mark.asyncio
    async def test_cleanup_expired_error_handling(self):
        """cleanup_expired handles errors per-stream gracefully."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()

        async def _scan_iter(**kwargs):
            yield b"prefix:stream:ch1:wh1"

        buf.redis.scan_iter = _scan_iter
        buf.redis.hgetall.side_effect = Exception("redis error")

        result = await buf.cleanup_expired("ch1")
        assert result == 0


# ─── delete_channel ──────────────────────────────────────────────────────────

class TestRedisBufferDeleteChannel:
    """Tests for delete_channel()."""

    @pytest.mark.asyncio
    async def test_delete_channel_not_connected(self):
        """delete_channel returns False when not connected."""
        buf = RedisBuffer()
        buf.redis = None
        result = await buf.delete_channel("ch1")
        assert result is False

    @pytest.mark.asyncio
    async def test_delete_channel_success(self):
        """delete_channel deletes keys and removes stats."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        buf._stats["ch1"] = {"delivered": 10}

        result = await buf.delete_channel("ch1")
        assert result is True
        buf.redis.delete.assert_awaited_once()
        assert "ch1" not in buf._stats

    @pytest.mark.asyncio
    async def test_delete_channel_with_webhook_ids(self):
        """delete_channel deletes per-webhook keys."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        buf._stats["ch1"] = {"delivered": 10}

        result = await buf.delete_channel("ch1", webhook_ids=["wh1", "wh2"])
        assert result is True
        call_args = buf.redis.delete.call_args
        # Should include per-webhook keys plus channel-level keys
        assert len(call_args[0]) >= 3

    @pytest.mark.asyncio
    async def test_delete_channel_error(self):
        """delete_channel returns False on Redis error."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        buf.redis.delete.side_effect = Exception("redis error")

        result = await buf.delete_channel("ch1")
        assert result is False


# ─── get_dead_letters ────────────────────────────────────────────────────────

class TestRedisBufferGetDeadLetters:
    """Tests for get_dead_letters()."""

    @pytest.mark.asyncio
    async def test_get_dead_letters_not_connected(self):
        """get_dead_letters returns empty list when not connected."""
        buf = RedisBuffer()
        buf.redis = None
        result = await buf.get_dead_letters("ch1")
        assert result == []

    @pytest.mark.asyncio
    async def test_get_dead_letters_success(self):
        """get_dead_letters parses DLQ entries."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()

        msg = _make_message()
        envelope = msg.to_envelope()
        dlq_entry = json.dumps({
            "stream_id": "1-0",
            "data": {"data": json.dumps(envelope)},
            "error": "test error",
            "failed_at": datetime.now(timezone.utc).isoformat(),
        })
        buf.redis.zrevrange.return_value = [dlq_entry.encode()]

        result = await buf.get_dead_letters("ch1")
        assert len(result) == 1
        assert result[0].state == MessageState.DEAD_LETTERED

    @pytest.mark.asyncio
    async def test_get_dead_letters_simple_envelope(self):
        """get_dead_letters handles entries with direct envelope data."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()

        msg = _make_message()
        envelope = msg.to_envelope()
        dlq_entry = json.dumps({
            "stream_id": "1-0",
            "data": envelope,  # Direct envelope, not nested
            "error": "test error",
        })
        buf.redis.zrevrange.return_value = [dlq_entry.encode()]

        result = await buf.get_dead_letters("ch1")
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_get_dead_letters_malformed_entry(self):
        """get_dead_letters skips malformed entries."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        buf.redis.zrevrange.return_value = [b"not-json"]

        result = await buf.get_dead_letters("ch1")
        assert result == []

    @pytest.mark.asyncio
    async def test_get_dead_letters_redis_error(self):
        """get_dead_letters returns empty list on Redis error."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        buf.redis.zrevrange.side_effect = Exception("redis error")

        result = await buf.get_dead_letters("ch1")
        assert result == []

    @pytest.mark.asyncio
    async def test_get_dead_letters_bytes_entry(self):
        """get_dead_letters decodes bytes entries."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()

        msg = _make_message()
        dlq_entry = json.dumps({
            "stream_id": "1-0",
            "data": msg.to_envelope(),
            "error": "test error",
        })
        buf.redis.zrevrange.return_value = [dlq_entry.encode()]

        result = await buf.get_dead_letters("ch1")
        assert len(result) == 1


# ─── health_check ────────────────────────────────────────────────────────────

class TestRedisBufferHealthCheck:
    """Tests for health_check()."""

    @pytest.mark.asyncio
    async def test_health_check_healthy(self):
        """health_check returns True when ping succeeds."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        result = await buf.health_check()
        assert result is True

    @pytest.mark.asyncio
    async def test_health_check_not_connected(self):
        """health_check returns False when not connected."""
        buf = RedisBuffer()
        buf.redis = None
        result = await buf.health_check()
        assert result is False

    @pytest.mark.asyncio
    async def test_health_check_ping_fails(self):
        """health_check returns False when ping raises."""
        buf = RedisBuffer()
        buf.redis = _mock_redis()
        buf.redis.ping.side_effect = Exception("connection lost")
        result = await buf.health_check()
        assert result is False


# ─── Key naming helpers ──────────────────────────────────────────────────────

class TestRedisBufferKeyNaming:
    """Tests for key naming helper methods."""

    @pytest.mark.asyncio
    async def test_stream_key_without_webhook_id(self):
        """_stream_key returns channel-level key."""
        buf = RedisBuffer(prefix="wc")
        assert buf._stream_key("ch1") == "wc:stream:ch1"

    @pytest.mark.asyncio
    async def test_stream_key_with_webhook_id(self):
        """_stream_key returns per-webhook key."""
        buf = RedisBuffer(prefix="wc")
        assert buf._stream_key("ch1", "wh1") == "wc:stream:ch1:wh1"

    @pytest.mark.asyncio
    async def test_dlq_key_without_webhook_id(self):
        """_dlq_key returns channel-level DLQ key."""
        buf = RedisBuffer(prefix="wc")
        assert buf._dlq_key("ch1") == "wc:dlq:ch1"

    @pytest.mark.asyncio
    async def test_dlq_key_with_webhook_id(self):
        """_dlq_key returns per-webhook DLQ key."""
        buf = RedisBuffer(prefix="wc")
        assert buf._dlq_key("ch1", "wh1") == "wc:dlq:ch1:wh1"

    @pytest.mark.asyncio
    async def test_consumer_group_name(self):
        """_consumer_group returns consistent group name."""
        buf = RedisBuffer(prefix="wc")
        assert buf._consumer_group("ch1") == "wc_consumers"

    @pytest.mark.asyncio
    async def test_stats_key(self):
        """_stats_key returns stats hash key."""
        buf = RedisBuffer(prefix="wc")
        assert buf._stats_key("ch1") == "wc:stats:ch1"
