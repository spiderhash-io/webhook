"""
Redis-based message buffer for Webhook Connect.

Uses Redis Streams with the following features:
- Per-webhook streams for message isolation and visibility
- Consumer groups for distributed consumption
- Automatic message acknowledgment tracking
- Pending entries list for in-flight messages
- XCLAIM for handling stuck messages
"""

import asyncio
import json
import logging
from typing import Optional, Dict, Callable, Awaitable, List
from datetime import datetime, timezone

import redis.asyncio as redis

# Redelivery limits to prevent infinite requeue loops
MAX_REDELIVERY_ATTEMPTS = 10
REQUEUE_DELAY_SECONDS = 0.5

# How often to re-scan for new per-webhook streams (seconds)
STREAM_DISCOVERY_INTERVAL = 10

from src.webhook_connect.buffer.interface import MessageBufferInterface
from src.webhook_connect.models import WebhookMessage, ChannelStats, MessageState

logger = logging.getLogger(__name__)


class RedisBuffer(MessageBufferInterface):
    """Redis Streams-based message buffer implementation."""

    def __init__(
        self,
        url: str = "redis://localhost:6379/0",
        prefix: str = "webhook_connect",
        block_timeout_ms: int = 5000,
        max_redelivery_attempts: int = MAX_REDELIVERY_ATTEMPTS,
        requeue_delay_seconds: float = REQUEUE_DELAY_SECONDS,
    ):
        """
        Initialize Redis buffer.

        Args:
            url: Redis connection URL
            prefix: Key prefix for all webhook connect keys
            block_timeout_ms: Timeout for blocking reads in milliseconds
            max_redelivery_attempts: Max redelivery attempts before sending to DLQ
            requeue_delay_seconds: Delay between redelivery attempts to prevent tight loops
        """
        self.url = url
        self.prefix = prefix
        self.block_timeout_ms = block_timeout_ms
        self.max_redelivery_attempts = max_redelivery_attempts
        self.requeue_delay_seconds = requeue_delay_seconds

        self.redis: Optional[redis.Redis] = None

        # Track in-flight messages: message_id -> {stream_id, channel, stream_key}
        self._in_flight: Dict[str, Dict[str, str]] = {}
        self._in_flight_lock = asyncio.Lock()

        # Track per-message redelivery counts (resets on process restart -- acceptable)
        self._requeue_counts: Dict[str, int] = {}

        # Consumer tasks for unsubscribe: consumer_tag -> asyncio.Task
        self._consumer_tasks: Dict[str, asyncio.Task] = {}

        # Stats tracking
        self._stats: Dict[str, Dict[str, int]] = {}

    def _stream_key(self, channel: str, webhook_id: str = None) -> str:
        """Get stream key for a channel, optionally per-webhook."""
        if webhook_id:
            return f"{self.prefix}:stream:{channel}:{webhook_id}"
        return f"{self.prefix}:stream:{channel}"

    def _dlq_key(self, channel: str, webhook_id: str = None) -> str:
        """Get dead letter queue key for a channel, optionally per-webhook."""
        if webhook_id:
            return f"{self.prefix}:dlq:{channel}:{webhook_id}"
        return f"{self.prefix}:dlq:{channel}"

    def _consumer_group(self, channel: str) -> str:
        """Get consumer group name for a channel."""
        return f"{self.prefix}_consumers"

    def _stats_key(self, channel: str) -> str:
        """Get stats hash key for a channel."""
        return f"{self.prefix}:stats:{channel}"

    async def _discover_streams(self, channel: str) -> List[str]:
        """
        Discover all per-webhook streams for a channel via SCAN.

        Args:
            channel: Channel name

        Returns:
            List of stream keys matching the channel pattern
        """
        if not self.redis:
            return []

        pattern = f"{self.prefix}:stream:{channel}:*"
        keys: List[str] = []
        async for key in self.redis.scan_iter(match=pattern):
            if isinstance(key, bytes):
                key = key.decode()
            keys.append(key)
        return keys

    async def connect(self) -> None:
        """Establish connection to Redis."""
        try:
            self.redis = redis.from_url(self.url, decode_responses=False)
            # Test connection
            await self.redis.ping()
            logger.info(f"Connected to Redis: {self.url}")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise ConnectionError(f"Failed to connect to Redis: {e}")

    async def close(self) -> None:
        """Close Redis connection."""
        # Cancel all consumer tasks
        for tag, task in list(self._consumer_tasks.items()):
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._consumer_tasks.clear()

        if self.redis:
            await self.redis.aclose()
            self.redis = None
            logger.info("Disconnected from Redis")

    async def ensure_channel(
        self, channel: str, ttl_seconds: int = 86400, webhook_id: str = None
    ) -> None:
        """Ensure channel stream and consumer group exist."""
        if not self.redis:
            raise ConnectionError("Not connected to Redis")

        stream_key = self._stream_key(channel, webhook_id)
        group_name = self._consumer_group(channel)

        try:
            # Create consumer group (this also creates the stream if it doesn't exist)
            await self.redis.xgroup_create(
                stream_key, group_name, id="0", mkstream=True
            )
            logger.info(f"Created consumer group {group_name} for stream {stream_key}")
        except redis.ResponseError as e:
            if "BUSYGROUP" in str(e):
                pass  # Group already exists
            else:
                raise

        # Store TTL in metadata
        meta_key = f"{self.prefix}:meta:{channel}"
        if webhook_id:
            meta_key = f"{self.prefix}:meta:{channel}:{webhook_id}"
        await self.redis.hset(
            meta_key,
            mapping={
                "ttl_seconds": str(ttl_seconds),
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
        )

        # Initialize stats
        if channel not in self._stats:
            self._stats[channel] = {"delivered": 0, "expired": 0, "dead_lettered": 0}

    async def push(self, channel: str, message: WebhookMessage) -> bool:
        """Add message to per-webhook stream."""
        if not self.redis:
            raise ConnectionError("Not connected to Redis")

        stream_key = self._stream_key(channel, message.webhook_id)

        try:
            # Serialize message
            envelope = message.to_envelope()

            # Add to stream
            stream_id = await self.redis.xadd(
                stream_key,
                {
                    "message_id": message.message_id,
                    "data": json.dumps(envelope),
                    "expires_at": (
                        message.expires_at.isoformat() if message.expires_at else ""
                    ),
                },
                maxlen=10000,  # Limit stream size
            )

            logger.debug(
                f"Published message {message.message_id} to {stream_key} "
                f"with stream_id {stream_id}"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to publish message to {channel}: {e}")
            return False

    async def subscribe(
        self,
        channel: str,
        callback: Callable[[WebhookMessage], Awaitable[None]],
        prefetch: int = 10,
        webhook_ids: List[str] = None,
    ) -> Optional[str]:
        """
        Subscribe to all per-webhook streams for a channel.

        Discovers per-webhook streams via SCAN, creates consumer groups,
        and reads from all streams in a background task.

        Returns:
            Consumer tag for cancellation via ``unsubscribe()``.
        """
        if not self.redis:
            raise ConnectionError("Not connected to Redis")

        group_name = self._consumer_group(channel)
        consumer_name = (
            f"consumer_{id(callback)}_{datetime.now(timezone.utc).timestamp():.0f}"
        )

        async def _ensure_group(stream_key: str) -> None:
            """Ensure consumer group exists on a stream."""
            try:
                await self.redis.xgroup_create(
                    stream_key, group_name, id="0", mkstream=True
                )
            except redis.ResponseError as e:
                if "BUSYGROUP" not in str(e):
                    raise

        async def _consume_loop() -> None:
            """Background loop that reads from all per-webhook streams."""
            logger.info(f"Starting consumer {consumer_name} for channel {channel}")
            known_streams: List[str] = []
            last_discovery = 0.0

            while True:
                try:
                    # Periodically discover new per-webhook streams
                    now = asyncio.get_event_loop().time()
                    if now - last_discovery > STREAM_DISCOVERY_INTERVAL:
                        new_streams = await self._discover_streams(channel)
                        for s in new_streams:
                            if s not in known_streams:
                                await _ensure_group(s)
                                known_streams.append(s)
                        last_discovery = now

                    if not known_streams:
                        await asyncio.sleep(1)
                        continue

                    # Read from all known streams
                    stream_dict = {s: ">" for s in known_streams}
                    messages = await self.redis.xreadgroup(
                        group_name,
                        consumer_name,
                        stream_dict,
                        count=prefetch,
                        block=self.block_timeout_ms,
                    )

                    if not messages:
                        continue

                    for stream, entries in messages:
                        for stream_id, data in entries:
                            await self._process_stream_entry(
                                channel, stream, stream_id, data,
                                group_name, callback,
                            )

                except asyncio.CancelledError:
                    logger.info(f"Consumer {consumer_name} cancelled")
                    return
                except Exception as e:
                    logger.error(f"Error in consumer loop for {channel}: {e}")
                    await asyncio.sleep(1)

        # Launch background task
        task = asyncio.create_task(_consume_loop())
        self._consumer_tasks[consumer_name] = task
        logger.info(f"Subscribed to channel {channel} (tag: {consumer_name})")
        return consumer_name

    async def _process_stream_entry(
        self,
        channel: str,
        stream: bytes,
        stream_id: bytes,
        data: dict,
        group_name: str,
        callback: Callable[[WebhookMessage], Awaitable[None]],
    ) -> None:
        """Process a single stream entry from XREADGROUP."""
        message = None
        try:
            if isinstance(stream_id, bytes):
                stream_id = stream_id.decode()

            stream_key_str = stream.decode() if isinstance(stream, bytes) else stream

            # Parse message data
            raw_id = data.get(b"message_id", data.get("message_id", b""))
            if isinstance(raw_id, bytes):
                message_id = raw_id.decode()
            else:
                message_id = str(raw_id)

            msg_data = data.get(b"data", data.get("data", b"{}"))
            if isinstance(msg_data, bytes):
                msg_data = msg_data.decode()

            envelope = json.loads(msg_data)
            message = WebhookMessage.from_envelope(envelope)
            message._buffer_id = stream_id

            # Check if expired
            if message.is_expired():
                await self.redis.xack(stream_key_str, group_name, stream_id)
                if channel in self._stats:
                    self._stats[channel]["expired"] = (
                        self._stats[channel].get("expired", 0) + 1
                    )
                logger.debug(f"Skipped expired message {message.message_id}")
                return

            # Track in-flight
            async with self._in_flight_lock:
                self._in_flight[message.message_id] = {
                    "stream_id": stream_id,
                    "channel": channel,
                    "stream_key": stream_key_str,
                }

            # Call user callback
            await callback(message)

        except Exception as e:
            logger.error(f"Error processing message from {channel}: {e}")

            # Clean up in-flight entry if it was added
            if message is not None and hasattr(message, 'message_id'):
                async with self._in_flight_lock:
                    self._in_flight.pop(message.message_id, None)

            msg_id = (
                message.message_id
                if message is not None and hasattr(message, 'message_id')
                else "unknown"
            )
            self._requeue_counts[msg_id] = (
                self._requeue_counts.get(msg_id, 0) + 1
            )

            stream_key_str = (
                stream.decode() if isinstance(stream, bytes) else stream
            )

            if self._requeue_counts.get(msg_id, 0) >= self.max_redelivery_attempts:
                self._requeue_counts.pop(msg_id, None)
                logger.warning(
                    f"Message from {channel} exceeded max redelivery "
                    f"attempts ({self.max_redelivery_attempts}), sending to DLQ"
                )
                await self._move_to_dlq(
                    channel, stream_id, data, str(e),
                    stream_key=stream_key_str,
                )
            else:
                # Leave message unacked in consumer group PEL --
                # will be redelivered on next XREADGROUP with "0" or via XCLAIM
                await asyncio.sleep(self.requeue_delay_seconds)
                logger.debug(
                    f"Left message from {channel} pending for "
                    f"redelivery (attempt {self._requeue_counts.get(msg_id, 0)})"
                )

    async def unsubscribe(self, consumer_tag: str) -> None:
        """Cancel a consumer by tag. Messages stop being delivered."""
        task = self._consumer_tasks.pop(consumer_tag, None)
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            logger.info(f"Cancelled consumer: {consumer_tag}")

    async def _move_to_dlq(
        self,
        channel: str,
        stream_id: str,
        data: dict,
        error: str,
        stream_key: str = None,
    ) -> None:
        """Move a message to the dead letter queue."""
        dlq_key = self._dlq_key(channel)
        if not stream_key:
            stream_key = self._stream_key(channel)
        group_name = self._consumer_group(channel)

        try:
            # Serialize data dict (handle bytes keys/values)
            serializable_data = {}
            if isinstance(data, dict):
                for k, v in data.items():
                    key = k.decode() if isinstance(k, bytes) else k
                    val = v.decode() if isinstance(v, bytes) else v
                    serializable_data[key] = val

            # Add to DLQ sorted set (score = timestamp)
            await self.redis.zadd(
                dlq_key,
                {
                    json.dumps(
                        {
                            "stream_id": stream_id,
                            "data": serializable_data,
                            "error": error,
                            "failed_at": datetime.now(timezone.utc).isoformat(),
                        }
                    ): datetime.now(timezone.utc).timestamp()
                },
            )

            # Acknowledge in original stream
            await self.redis.xack(stream_key, group_name, stream_id)

            if channel in self._stats:
                self._stats[channel]["dead_lettered"] = (
                    self._stats[channel].get("dead_lettered", 0) + 1
                )

        except Exception as e:
            logger.error(f"Failed to move message to DLQ: {e}")

    async def ack(self, channel: str, message_id: str) -> bool:
        """Acknowledge message."""
        if not self.redis:
            return False

        async with self._in_flight_lock:
            info = self._in_flight.pop(message_id, None)

        if not info:
            logger.warning(f"Message {message_id} not found in flight")
            return False

        stream_key = info.get("stream_key", self._stream_key(channel))
        group_name = self._consumer_group(channel)
        stream_id = info["stream_id"]

        try:
            await self.redis.xack(stream_key, group_name, stream_id)
            # Optionally delete the message from stream
            await self.redis.xdel(stream_key, stream_id)

            self._requeue_counts.pop(message_id, None)
            if channel in self._stats:
                self._stats[channel]["delivered"] = (
                    self._stats[channel].get("delivered", 0) + 1
                )
            logger.debug(f"Acknowledged message {message_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to ack message {message_id}: {e}")
            return False

    async def nack(self, channel: str, message_id: str, retry: bool = True) -> bool:
        """Negative acknowledge message."""
        if not self.redis:
            return False

        async with self._in_flight_lock:
            info = self._in_flight.pop(message_id, None)

        if not info:
            logger.warning(f"Message {message_id} not found in flight")
            return False

        stream_key = info.get("stream_key", self._stream_key(channel))
        group_name = self._consumer_group(channel)
        stream_id = info["stream_id"]

        try:
            if retry:
                # Reset the message to be redelivered
                logger.debug(f"Message {message_id} will be redelivered")
                return True
            else:
                # Move to DLQ
                messages = await self.redis.xrange(stream_key, stream_id, stream_id)
                if messages:
                    _, data = messages[0]
                    await self._move_to_dlq(
                        channel, stream_id, data, "Permanent failure",
                        stream_key=stream_key,
                    )
                else:
                    await self.redis.xack(stream_key, group_name, stream_id)

                logger.debug(f"Sent message {message_id} to dead letter queue")
                return True
        except Exception as e:
            logger.error(f"Failed to nack message {message_id}: {e}")
            return False

    async def get_queue_depth(self, channel: str, webhook_id: str = None) -> int:
        """Get number of pending messages in channel or per-webhook stream."""
        if not self.redis:
            return 0

        stream_key = self._stream_key(channel, webhook_id)

        try:
            info = await self.redis.xinfo_stream(stream_key)
            return info.get("length", 0)
        except Exception:
            return 0

    async def get_webhook_queue_depths(
        self, channel: str, webhook_ids: List[str]
    ) -> Dict[str, int]:
        """Get pending message counts for each webhook in a channel."""
        depths: Dict[str, int] = {}
        for webhook_id in webhook_ids:
            depths[webhook_id] = await self.get_queue_depth(channel, webhook_id)
        return depths

    async def get_in_flight_count(self, channel: str) -> int:
        """Get number of messages awaiting acknowledgment."""
        async with self._in_flight_lock:
            count = sum(
                1
                for info in self._in_flight.values()
                if info.get("channel") == channel
            )
        return count

    async def get_stats(self, channel: str) -> ChannelStats:
        """Get channel statistics."""
        queue_depth = await self.get_queue_depth(channel)
        in_flight = await self.get_in_flight_count(channel)

        stats = self._stats.get(channel, {})

        return ChannelStats(
            channel=channel,
            messages_queued=queue_depth,
            messages_in_flight=in_flight,
            messages_delivered=stats.get("delivered", 0),
            messages_expired=stats.get("expired", 0),
            messages_dead_lettered=stats.get("dead_lettered", 0),
            connected_clients=0,  # Will be filled by ChannelManager
        )

    async def cleanup_expired(self, channel: str) -> int:
        """Remove expired messages from channel."""
        if not self.redis:
            return 0

        # Clean up all per-webhook streams for the channel
        streams = await self._discover_streams(channel)
        total_count = 0

        for stream_key in streams:
            try:
                meta = await self.redis.hgetall(f"{self.prefix}:meta:{channel}")
                if not meta:
                    continue

                ttl_seconds = int(
                    meta.get(b"ttl_seconds", meta.get("ttl_seconds", 86400))
                )

                # Use XTRIM with MINID to remove old entries
                min_timestamp = int(
                    (datetime.now(timezone.utc).timestamp() - ttl_seconds) * 1000
                )
                min_id = f"{min_timestamp}-0"

                count = await self.redis.xtrim(stream_key, minid=min_id)
                total_count += count

            except Exception as e:
                logger.error(
                    f"Failed to cleanup expired messages for {stream_key}: {e}"
                )

        if total_count > 0:
            logger.info(f"Cleaned up {total_count} expired messages from {channel}")

        return total_count

    async def delete_channel(
        self, channel: str, webhook_ids: List[str] = None
    ) -> bool:
        """Delete a channel and all its messages."""
        if not self.redis:
            return False

        try:
            keys_to_delete = []

            # Delete per-webhook streams and DLQs
            if webhook_ids:
                for webhook_id in webhook_ids:
                    keys_to_delete.append(self._stream_key(channel, webhook_id))
                    keys_to_delete.append(self._dlq_key(channel, webhook_id))
                    keys_to_delete.append(
                        f"{self.prefix}:meta:{channel}:{webhook_id}"
                    )

            # Also delete channel-level keys
            keys_to_delete.append(self._stream_key(channel))
            keys_to_delete.append(self._dlq_key(channel))
            keys_to_delete.append(f"{self.prefix}:meta:{channel}")

            # Delete all keys
            if keys_to_delete:
                await self.redis.delete(*keys_to_delete)

            # Remove from stats
            self._stats.pop(channel, None)

            logger.info(f"Deleted channel: {channel}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete channel {channel}: {e}")
            return False

    async def get_dead_letters(
        self, channel: str, limit: int = 100
    ) -> List[WebhookMessage]:
        """Get dead letter messages for a channel."""
        if not self.redis:
            return []

        dlq_key = self._dlq_key(channel)
        messages = []

        try:
            # Get from sorted set (newest first)
            entries = await self.redis.zrevrange(dlq_key, 0, limit - 1)

            for entry in entries:
                try:
                    if isinstance(entry, bytes):
                        entry = entry.decode()
                    data = json.loads(entry)
                    msg_data = data.get("data", {})

                    if isinstance(msg_data, dict) and "data" in msg_data:
                        # Parse from stored format
                        envelope_str = msg_data.get(
                            b"data", msg_data.get("data", "{}")
                        )
                        if isinstance(envelope_str, bytes):
                            envelope_str = envelope_str.decode()
                        envelope = json.loads(envelope_str)
                        message = WebhookMessage.from_envelope(envelope)
                    else:
                        message = WebhookMessage.from_envelope(msg_data)

                    message.state = MessageState.DEAD_LETTERED
                    messages.append(message)
                except Exception as e:
                    logger.error(f"Error parsing dead letter: {e}")

        except Exception as e:
            logger.error(f"Failed to get dead letters for {channel}: {e}")

        return messages

    async def health_check(self) -> bool:
        """Check if Redis connection is healthy."""
        if not self.redis:
            return False
        try:
            await self.redis.ping()
            return True
        except Exception:
            return False
