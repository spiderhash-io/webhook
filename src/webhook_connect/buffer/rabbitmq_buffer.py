"""
RabbitMQ-based message buffer for Webhook Connect.

Uses RabbitMQ queues with the following features:
- Per-webhook durable queues for message persistence and visibility
- Topic exchange for flexible routing
- Dead letter exchange for failed messages
- Message TTL support
- Consumer acknowledgment mode
- Direct per-webhook queue consumption (no collector queue)
"""

import asyncio
import json
import logging
from typing import Optional, Dict, Callable, Awaitable, List
from datetime import datetime

import aio_pika

# Redelivery limits to prevent infinite requeue loops
MAX_REDELIVERY_ATTEMPTS = 10
REQUEUE_DELAY_SECONDS = 0.5

from aio_pika import connect_robust, Message, DeliveryMode, ExchangeType
from aio_pika.abc import AbstractIncomingMessage

from src.webhook_connect.buffer.interface import MessageBufferInterface
from src.webhook_connect.models import WebhookMessage, ChannelStats, MessageState

logger = logging.getLogger(__name__)


class RabbitMQBuffer(MessageBufferInterface):
    """RabbitMQ-based message buffer implementation with per-webhook queues."""

    def __init__(
        self,
        url: str = "amqp://guest:guest@localhost:5672/",
        exchange_name: str = "webhook_connect",
        prefetch_count: int = 100,
        max_redelivery_attempts: int = MAX_REDELIVERY_ATTEMPTS,
        requeue_delay_seconds: float = REQUEUE_DELAY_SECONDS,
    ):
        """
        Initialize RabbitMQ buffer.

        Args:
            url: AMQP connection URL
            exchange_name: Name of the exchange for webhook connect
            prefetch_count: Number of messages to prefetch per consumer
            max_redelivery_attempts: Max requeue attempts before sending to DLQ
            requeue_delay_seconds: Delay between requeue attempts to prevent tight loops
        """
        self.url = url
        self.exchange_name = exchange_name
        self.prefetch_count = prefetch_count
        self.max_redelivery_attempts = max_redelivery_attempts
        self.requeue_delay_seconds = requeue_delay_seconds

        self.connection: Optional[aio_pika.RobustConnection] = None
        self.channel: Optional[aio_pika.Channel] = None
        self.exchange: Optional[aio_pika.Exchange] = None
        self.dlx_exchange: Optional[aio_pika.Exchange] = None

        # Track in-flight messages for ack/nack
        self._in_flight: Dict[str, AbstractIncomingMessage] = {}
        self._in_flight_lock = asyncio.Lock()

        # Track per-message requeue counts (resets on process restart — acceptable)
        self._requeue_counts: Dict[str, int] = {}

        # Stats tracking
        self._stats: Dict[str, Dict[str, int]] = {}

        # Per-channel consumer tracking for direct per-webhook consumption
        self._channel_consumers: Dict[str, Dict[str, str]] = {}  # channel -> {webhook_id: consumer_tag}
        self._channel_callbacks: Dict[str, Callable] = {}  # channel -> delivery callback
        self._consumer_queues: Dict[str, object] = {}  # consumer_tag -> queue object (for cancellation)

    def _queue_name(self, channel: str, webhook_id: str = None) -> str:
        """
        Get queue name for a channel, optionally per-webhook.

        Args:
            channel: Channel name
            webhook_id: If provided, returns per-webhook queue name
        """
        if webhook_id:
            return f"{self.exchange_name}.{channel}.{webhook_id}"
        return f"{self.exchange_name}.{channel}"

    def _dlq_name(self, channel: str, webhook_id: str = None) -> str:
        """
        Get dead letter queue name for a channel, optionally per-webhook.

        Args:
            channel: Channel name
            webhook_id: If provided, returns per-webhook DLQ name
        """
        if webhook_id:
            return f"{self.exchange_name}.{channel}.{webhook_id}.dlq"
        return f"{self.exchange_name}.{channel}.dlq"

    def _routing_key(self, channel: str, webhook_id: str = "*") -> str:
        """
        Get routing key for topic exchange.

        Args:
            channel: Channel name
            webhook_id: Webhook ID or '*' wildcard for subscribing to all
        """
        return f"{channel}.{webhook_id}"

    async def connect(self) -> None:
        """Establish connection to RabbitMQ."""
        try:
            self.connection = await connect_robust(self.url)
            self.channel = await self.connection.channel()
            await self.channel.set_qos(prefetch_count=self.prefetch_count)

            # Create main exchange for webhook messages (TOPIC for per-webhook routing)
            self.exchange = await self.channel.declare_exchange(
                self.exchange_name, ExchangeType.TOPIC, durable=True
            )

            # Create dead letter exchange (TOPIC to match)
            self.dlx_exchange = await self.channel.declare_exchange(
                f"{self.exchange_name}.dlx", ExchangeType.TOPIC, durable=True
            )

            logger.info(f"Connected to RabbitMQ: {self.url}")

        except Exception as e:
            logger.error(f"Failed to connect to RabbitMQ: {e}")
            raise ConnectionError(f"Failed to connect to RabbitMQ: {e}")

    async def close(self) -> None:
        """Close RabbitMQ connection."""
        if self.connection:
            await self.connection.close()
            self.connection = None
            self.channel = None
            self.exchange = None
            logger.info("Disconnected from RabbitMQ")

    async def ensure_channel(
        self, channel: str, ttl_seconds: int = 86400, webhook_id: str = None
    ) -> None:
        """
        Ensure per-webhook queue exists with proper configuration.

        If webhook_id is provided, creates a dedicated queue for that webhook.
        Otherwise, this is a no-op (per-webhook queues are the unit of storage).
        """
        if not self.channel:
            raise ConnectionError("Not connected to RabbitMQ")

        if not webhook_id:
            # Channel-level ensure is a no-op — per-webhook queues are the unit
            if channel not in self._stats:
                self._stats[channel] = {"delivered": 0, "expired": 0, "dead_lettered": 0}
            return

        queue_name = self._queue_name(channel, webhook_id)
        dlq_name = self._dlq_name(channel, webhook_id)
        routing_key = self._routing_key(channel, webhook_id)

        # Create dead letter queue first
        dlq = await self.channel.declare_queue(
            dlq_name, durable=True, arguments={"x-queue-type": "classic"}
        )
        await dlq.bind(self.dlx_exchange, routing_key=routing_key)

        # Create main queue with DLX configuration
        queue = await self.channel.declare_queue(
            queue_name,
            durable=True,
            arguments={
                "x-dead-letter-exchange": f"{self.exchange_name}.dlx",
                "x-dead-letter-routing-key": routing_key,
                "x-message-ttl": ttl_seconds * 1000,  # Convert to milliseconds
                "x-queue-type": "classic",
            },
        )
        await queue.bind(self.exchange, routing_key=routing_key)

        # Initialize stats for this channel
        if channel not in self._stats:
            self._stats[channel] = {"delivered": 0, "expired": 0, "dead_lettered": 0}

        logger.info(f"Ensured webhook queue: {queue_name} (TTL {ttl_seconds}s)")

    async def push(self, channel: str, message: WebhookMessage) -> bool:
        """Add message to per-webhook queue via topic exchange."""
        if not self.exchange:
            raise ConnectionError("Not connected to RabbitMQ")

        try:
            # Serialize message to JSON
            body = json.dumps(message.to_envelope()).encode()

            # Create AMQP message
            amqp_message = Message(
                body=body,
                message_id=message.message_id,
                timestamp=message.received_at,
                delivery_mode=DeliveryMode.PERSISTENT,
                headers={"channel": channel, "webhook_id": message.webhook_id},
            )

            # Route to per-webhook queue
            routing_key = self._routing_key(channel, message.webhook_id)
            await self.exchange.publish(amqp_message, routing_key=routing_key)

            logger.debug(
                f"Published message {message.message_id} to {routing_key}"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to publish message to {channel}: {e}")
            return False

    def _make_message_handler(
        self,
        channel: str,
        callback: Callable[[WebhookMessage], Awaitable[None]],
    ) -> Callable[[AbstractIncomingMessage], Awaitable[None]]:
        """
        Create an AMQP message handler that parses messages and calls the delivery callback.

        Args:
            channel: Channel name (for logging and stats)
            callback: Async delivery callback from ChannelManager
        """

        async def message_handler(amqp_message: AbstractIncomingMessage):
            """Handle incoming AMQP message from a per-webhook queue."""
            try:
                # Parse message
                data = json.loads(amqp_message.body.decode())
                message = WebhookMessage.from_envelope(data)
                message._buffer_id = amqp_message.message_id

                # Track in-flight
                async with self._in_flight_lock:
                    self._in_flight[message.message_id] = amqp_message

                # Call user callback
                await callback(message)

            except Exception as e:
                logger.error(f"Error processing message from {channel}: {e}")

                # Clean up in-flight entry if it was added
                if 'message' in locals() and message.message_id:
                    async with self._in_flight_lock:
                        self._in_flight.pop(message.message_id, None)

                # Track requeue count in-memory
                msg_id = amqp_message.message_id or "unknown"
                self._requeue_counts[msg_id] = self._requeue_counts.get(msg_id, 0) + 1

                if self._requeue_counts[msg_id] >= self.max_redelivery_attempts:
                    self._requeue_counts.pop(msg_id, None)
                    logger.warning(
                        f"Message from {channel} exceeded max redelivery "
                        f"attempts ({self.max_redelivery_attempts}), sending to DLQ"
                    )
                    await amqp_message.reject(requeue=False)
                    if channel in self._stats:
                        self._stats[channel]["dead_lettered"] = (
                            self._stats[channel].get("dead_lettered", 0) + 1
                        )
                else:
                    await asyncio.sleep(self.requeue_delay_seconds)
                    await amqp_message.reject(requeue=True)
                    logger.debug(
                        f"Requeued message from {channel} for redelivery "
                        f"(attempt {self._requeue_counts[msg_id]})"
                    )

        return message_handler

    async def _start_webhook_consumer(
        self,
        channel: str,
        webhook_id: str,
        callback: Callable[[WebhookMessage], Awaitable[None]],
    ) -> Optional[str]:
        """
        Start consuming from a single per-webhook queue.

        Args:
            channel: Channel name
            webhook_id: Webhook ID whose queue to consume
            callback: Delivery callback

        Returns:
            Consumer tag, or None if queue doesn't exist
        """
        if not self.channel:
            return None

        queue_name = self._queue_name(channel, webhook_id)

        try:
            # Declare passively to get a reference to the existing queue
            queue = await self.channel.declare_queue(queue_name, passive=True)
        except Exception:
            logger.warning(f"Per-webhook queue {queue_name} not found, skipping consumer")
            return None

        handler = self._make_message_handler(channel, callback)
        consumer_tag = await queue.consume(handler)

        # Track the consumer and queue reference (for cancellation)
        if channel not in self._channel_consumers:
            self._channel_consumers[channel] = {}
        self._channel_consumers[channel][webhook_id] = consumer_tag
        self._consumer_queues[consumer_tag] = queue

        logger.info(
            f"Started consumer on {queue_name} (tag: {consumer_tag})"
        )
        return consumer_tag

    async def subscribe(
        self,
        channel: str,
        callback: Callable[[WebhookMessage], Awaitable[None]],
        prefetch: int = 10,
        webhook_ids: List[str] = None,
    ) -> Optional[str]:
        """
        Subscribe to per-webhook queues for a channel by consuming directly
        from each durable per-webhook queue.

        Messages are consumed from the same queues they are buffered in,
        eliminating duplicate delivery. When unsubscribed, unconsumed
        messages remain in the durable per-webhook queues (deferred consumption).

        Args:
            channel: Channel name
            callback: Async delivery callback
            prefetch: Number of messages to prefetch (unused, set at connection level)
            webhook_ids: List of webhook IDs whose queues to consume from

        Returns:
            Composite consumer tag for cancellation via ``unsubscribe()``.
        """
        if not self.channel:
            raise ConnectionError("Not connected to RabbitMQ")

        # Store callback for dynamic additions via subscribe_webhook()
        self._channel_callbacks[channel] = callback
        self._channel_consumers[channel] = {}

        # Start a consumer on each known per-webhook queue
        started = 0
        for webhook_id in (webhook_ids or []):
            tag = await self._start_webhook_consumer(channel, webhook_id, callback)
            if tag:
                started += 1

        composite_tag = f"channel_sub:{channel}"
        logger.info(
            f"Subscribed to channel {channel}: {started} per-webhook consumer(s) "
            f"(tag: {composite_tag})"
        )
        return composite_tag

    async def subscribe_webhook(
        self,
        channel: str,
        webhook_id: str,
        callback: Callable[[WebhookMessage], Awaitable[None]] = None,
    ) -> Optional[str]:
        """
        Add a consumer for a single webhook queue on an already-subscribed channel.

        Used when a new webhook registers while a connector is already connected.

        Args:
            channel: Channel name
            webhook_id: Webhook ID to start consuming
            callback: Async callback (uses stored callback if None)

        Returns:
            Consumer tag, or None on failure
        """
        cb = callback or self._channel_callbacks.get(channel)
        if not cb:
            logger.warning(f"No callback stored for channel {channel}, cannot subscribe webhook {webhook_id}")
            return None

        # Skip if already consuming this webhook
        if webhook_id in self._channel_consumers.get(channel, {}):
            logger.debug(f"Already consuming webhook {webhook_id} on channel {channel}")
            return self._channel_consumers[channel][webhook_id]

        return await self._start_webhook_consumer(channel, webhook_id, cb)

    async def unsubscribe(self, consumer_tag: str) -> None:
        """
        Cancel consumer(s) by tag.

        Handles both composite tags (``channel_sub:{channel}``) that cancel
        all per-webhook consumers for a channel, and individual consumer tags.
        """
        if not self.channel:
            return

        if consumer_tag.startswith("channel_sub:"):
            # Composite tag — cancel all per-webhook consumers for this channel
            channel = consumer_tag[len("channel_sub:"):]
            consumers = self._channel_consumers.pop(channel, {})
            self._channel_callbacks.pop(channel, None)

            for webhook_id, tag in consumers.items():
                try:
                    queue = self._consumer_queues.pop(tag, None)
                    if queue:
                        await queue.cancel(tag)
                    else:
                        logger.warning(f"No queue reference for consumer {tag}, skipping cancel")
                except Exception as e:
                    logger.error(f"Failed to cancel consumer for {webhook_id}: {e}")

            logger.info(
                f"Cancelled {len(consumers)} consumer(s) for channel {channel}"
            )
        else:
            # Single consumer tag (backward compat)
            try:
                queue = self._consumer_queues.pop(consumer_tag, None)
                if queue:
                    await queue.cancel(consumer_tag)
                else:
                    logger.warning(f"No queue reference for consumer {consumer_tag}, skipping cancel")
                logger.info(f"Cancelled consumer: {consumer_tag}")
            except Exception as e:
                logger.error(f"Failed to cancel consumer {consumer_tag}: {e}")

    async def ack(self, channel: str, message_id: str) -> bool:
        """Acknowledge message."""
        async with self._in_flight_lock:
            amqp_message = self._in_flight.pop(message_id, None)

        if not amqp_message:
            logger.warning(f"Message {message_id} not found in flight")
            return False

        try:
            await amqp_message.ack()
            self._requeue_counts.pop(message_id, None)
            if channel in self._stats:
                self._stats[channel]["delivered"] += 1
            logger.debug(f"Acknowledged message {message_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to ack message {message_id}: {e}")
            return False

    async def nack(self, channel: str, message_id: str, retry: bool = True) -> bool:
        """Negative acknowledge message."""
        async with self._in_flight_lock:
            amqp_message = self._in_flight.pop(message_id, None)

        if not amqp_message:
            logger.warning(f"Message {message_id} not found in flight")
            return False

        try:
            if retry:
                # Requeue for retry
                await amqp_message.reject(requeue=True)
                logger.debug(f"Requeued message {message_id} for retry")
            else:
                # Send to dead letter queue
                await amqp_message.reject(requeue=False)
                if channel in self._stats:
                    self._stats[channel]["dead_lettered"] += 1
                logger.debug(f"Sent message {message_id} to dead letter queue")
            return True
        except Exception as e:
            logger.error(f"Failed to nack message {message_id}: {e}")
            return False

    async def get_queue_depth(self, channel: str, webhook_id: str = None) -> int:
        """
        Get number of pending messages.

        If webhook_id is provided, returns count for that specific webhook queue.
        Otherwise returns 0 (per-webhook queues are the unit of storage).

        Uses a temporary AMQP channel for the passive declare so that a 404
        (queue not found) doesn't close the main publish/consume channel.
        """
        if not self.connection:
            return 0

        try:
            queue_name = self._queue_name(channel, webhook_id)
            # Use a temporary channel — passive declare on non-existent queue
            # closes the AMQP channel, which would break publish/consume.
            temp_channel = await self.connection.channel()
            try:
                queue = await temp_channel.declare_queue(queue_name, passive=True)
                return queue.declaration_result.message_count
            finally:
                await temp_channel.close()
        except Exception:
            pass
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
            # Count messages for this channel
            count = sum(
                1
                for msg in self._in_flight.values()
                if msg.headers and msg.headers.get("channel") == channel
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
        # RabbitMQ handles TTL automatically via x-message-ttl
        # This method is mainly for manual cleanup if needed
        return 0

    async def delete_channel(
        self, channel: str, webhook_ids: List[str] = None
    ) -> bool:
        """Delete a channel and all its messages."""
        if not self.channel:
            return False

        try:
            # Delete per-webhook queues
            if webhook_ids:
                for webhook_id in webhook_ids:
                    queue_name = self._queue_name(channel, webhook_id)
                    dlq_name = self._dlq_name(channel, webhook_id)
                    try:
                        await self.channel.queue_delete(queue_name)
                        await self.channel.queue_delete(dlq_name)
                    except Exception:
                        pass

            # Clean up consumer tracking
            consumers = self._channel_consumers.pop(channel, {})
            for tag in consumers.values():
                self._consumer_queues.pop(tag, None)
            self._channel_callbacks.pop(channel, None)

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
        if not self.channel:
            return []

        messages = []
        dlq_name = self._dlq_name(channel)

        try:
            queue = await self.channel.get_queue(dlq_name, ensure=False)
            if not queue:
                return []

            # Get messages without consuming (peek)
            count = 0
            async with queue.iterator() as queue_iter:
                async for amqp_message in queue_iter:
                    try:
                        data = json.loads(amqp_message.body.decode())
                        message = WebhookMessage.from_envelope(data)
                        message.state = MessageState.DEAD_LETTERED
                        messages.append(message)

                        # Requeue message (we're just peeking)
                        await amqp_message.reject(requeue=True)

                        count += 1
                        if count >= limit:
                            break
                    except Exception as e:
                        logger.error(f"Error reading dead letter: {e}")
                        await amqp_message.reject(requeue=True)

        except Exception as e:
            logger.error(f"Failed to get dead letters for {channel}: {e}")

        return messages

    async def health_check(self) -> bool:
        """Check if RabbitMQ connection is healthy."""
        if not self.connection or self.connection.is_closed:
            return False
        return True
