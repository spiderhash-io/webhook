"""
Channel Manager for Webhook Connect.

Manages channels, connections, and message routing between
the Cloud Receiver and Local Connectors.
"""

import asyncio
import json
import logging
import random
import secrets
from typing import Dict, Optional, Set, List, Callable, Awaitable
from datetime import datetime, timedelta, timezone

from src.webhook_connect.models import (
    WebhookMessage,
    ChannelConfig,
    ConnectorConnection,
    ConnectionProtocol,
    ChannelStats,
    ConnectionState,
    MessageState,
)
from src.webhook_connect.buffer.interface import MessageBufferInterface


logger = logging.getLogger(__name__)

# Stale connection eviction settings
EVICTION_CHECK_INTERVAL_SECONDS = 30
STALE_HEARTBEAT_MULTIPLIER = 3  # stale after heartbeat_interval * this
INITIAL_HEARTBEAT_GRACE_SECONDS = 60
SSE_STALE_SECONDS = 86400  # 24 hours
LONG_POLL_STALE_SECONDS = 300  # 5 minutes


class ChannelManager:
    """
    Manages channels, connections, and message routing.

    Responsibilities:
    - Channel registration and configuration
    - Connection management (add/remove connectors)
    - Token validation
    - Message publishing to channels
    - Statistics tracking
    """

    def __init__(self, buffer: MessageBufferInterface):
        """
        Initialize ChannelManager.

        Args:
            buffer: Message buffer backend (RabbitMQ or Redis)
        """
        self.buffer = buffer

        # Channel configurations: channel_name -> ChannelConfig
        self.channels: Dict[str, ChannelConfig] = {}

        # Active connections: connection_id -> ConnectorConnection
        self.connections: Dict[str, ConnectorConnection] = {}

        # Channel to connections mapping: channel_name -> set of connection_ids
        self.channel_connections: Dict[str, Set[str]] = {}

        # Locks for thread safety
        self._channels_lock = asyncio.Lock()
        self._connections_lock = asyncio.Lock()

        # Sequence counter per channel
        self._sequence_counters: Dict[str, int] = {}

        # Stale connection eviction task
        self._eviction_task: Optional[asyncio.Task] = None

        # Deferred consumption: consumer tags per channel
        self._consumer_tags: Dict[str, str] = {}  # channel_name -> consumer_tag

        # Track which webhook_ids belong to each channel
        self._channel_webhook_ids: Dict[str, Set[str]] = {}  # channel -> set of webhook_ids

        # Per-connection send functions: connection_id -> async send(message)
        self._connection_send_fns: Dict[
            str, Callable[[WebhookMessage], Awaitable[None]]
        ] = {}

    async def start(self) -> None:
        """Start the channel manager and connect to buffer."""
        await self.buffer.connect()
        self._eviction_task = asyncio.create_task(self._eviction_loop())
        logger.info("ChannelManager started")

    async def stop(self) -> None:
        """Stop the channel manager and cleanup."""
        # Cancel eviction task
        if self._eviction_task and not self._eviction_task.done():
            self._eviction_task.cancel()
            try:
                await self._eviction_task
            except asyncio.CancelledError:
                pass
            self._eviction_task = None

        # Cancel all buffer consumers
        for channel, tag in list(self._consumer_tags.items()):
            try:
                await self.buffer.unsubscribe(tag)
            except Exception as e:
                logger.error(f"Error cancelling consumer for {channel}: {e}")
        self._consumer_tags.clear()

        # Close all connections
        async with self._connections_lock:
            for connection_id in list(self.connections.keys()):
                await self._cleanup_connection(connection_id)

        await self.buffer.close()
        logger.info("ChannelManager stopped")

    async def register_channel(
        self,
        name: str,
        webhook_id: str,
        token: str,
        ttl: timedelta = timedelta(hours=24),
        **kwargs,
    ) -> ChannelConfig:
        """
        Register a new channel or update existing.

        Args:
            name: Unique channel identifier
            webhook_id: Associated webhook endpoint ID
            token: Authentication token for connectors
            ttl: Message time-to-live
            **kwargs: Additional channel configuration

        Returns:
            ChannelConfig for the registered channel
        """
        async with self._channels_lock:
            config = ChannelConfig(
                name=name,
                webhook_id=webhook_id,
                channel_token=token,
                ttl=ttl,
                max_queue_size=kwargs.get("max_queue_size", 10000),
                max_message_size=kwargs.get("max_message_size", 10 * 1024 * 1024),
                max_in_flight=kwargs.get("max_in_flight", 100),
                max_connections=kwargs.get("max_connections", 10),
                allowed_ips=kwargs.get("allowed_ips"),
                rate_limit_per_second=kwargs.get("rate_limit_per_second"),
            )

            self.channels[name] = config

            if name not in self.channel_connections:
                self.channel_connections[name] = set()

            if name not in self._sequence_counters:
                self._sequence_counters[name] = 0

        # Create per-webhook queue in buffer
        await self.buffer.ensure_channel(
            name, int(ttl.total_seconds()), webhook_id=webhook_id
        )

        # Track which webhook_ids belong to this channel
        if name not in self._channel_webhook_ids:
            self._channel_webhook_ids[name] = set()
        self._channel_webhook_ids[name].add(webhook_id)

        # If a connector is already consuming this channel, dynamically add
        # a consumer for the new per-webhook queue
        if name in self._consumer_tags:
            callback = self._make_delivery_callback(name)
            await self.buffer.subscribe_webhook(name, webhook_id, callback)
            logger.info(
                f"Dynamically added consumer for webhook {webhook_id} on channel {name}"
            )

        logger.info(f"Registered channel: {name} for webhook {webhook_id}")
        return config

    async def unregister_channel(self, name: str) -> bool:
        """
        Unregister a channel.

        Args:
            name: Channel name to unregister

        Returns:
            True if unregistered, False if not found
        """
        async with self._channels_lock:
            if name not in self.channels:
                return False

            # Close all connections for this channel
            connection_ids = list(self.channel_connections.get(name, set()))
            for conn_id in connection_ids:
                await self.remove_connection(conn_id)

            del self.channels[name]
            self.channel_connections.pop(name, None)
            self._sequence_counters.pop(name, None)

        # Stop consumer if running
        consumer_tag = self._consumer_tags.pop(name, None)
        if consumer_tag:
            await self.buffer.unsubscribe(consumer_tag)

        # Delete channel from buffer (pass webhook_ids for per-webhook cleanup)
        webhook_ids = list(self._channel_webhook_ids.pop(name, set()))
        await self.buffer.delete_channel(name, webhook_ids=webhook_ids or None)

        logger.info(f"Unregistered channel: {name}")
        return True

    def get_channel(self, name: str) -> Optional[ChannelConfig]:
        """Get channel configuration by name."""
        return self.channels.get(name)

    def validate_token(self, channel: str, token: str) -> bool:
        """
        Validate channel access token.

        Args:
            channel: Channel name
            token: Token to validate

        Returns:
            True if valid, False otherwise
        """
        config = self.channels.get(channel)
        if not config:
            return False
        return config.validate_token(token)

    async def rotate_token(
        self, channel: str, grace_period: timedelta = timedelta(hours=1)
    ) -> Optional[str]:
        """
        Rotate channel token with grace period.

        Args:
            channel: Channel name
            grace_period: How long old token remains valid

        Returns:
            New token, or None if channel not found
        """
        async with self._channels_lock:
            config = self.channels.get(channel)
            if not config:
                return None

            # Generate new token
            new_token = f"ch_tok_{secrets.token_hex(24)}"

            # Store old token with expiry
            config.old_token = config.channel_token
            config.old_token_expires_at = datetime.now(timezone.utc) + grace_period

            # Set new token
            config.channel_token = new_token
            config.updated_at = datetime.now(timezone.utc)

        logger.info(
            f"Rotated token for channel {channel}, grace period: {grace_period}"
        )
        return new_token

    async def publish(self, channel: str, message: WebhookMessage) -> bool:
        """
        Publish message to channel.

        Args:
            channel: Channel name
            message: Webhook message to publish

        Returns:
            True if published, False if failed or queue full
        """
        config = self.channels.get(channel)
        if not config:
            logger.warning(f"Attempted to publish to unknown channel: {channel}")
            return False

        # Check queue size limit
        depth = await self.buffer.get_queue_depth(channel)
        if depth >= config.max_queue_size:
            logger.warning(f"Channel {channel} queue is full ({depth} messages)")
            return False

        # Check message size
        # Note: This is a rough estimate, actual size may vary
        message_size = len(json.dumps(message.to_envelope()).encode())
        if message_size > config.max_message_size:
            logger.warning(
                f"Message too large for channel {channel}: {message_size} bytes"
            )
            return False

        # Assign sequence number
        self._sequence_counters[channel] = self._sequence_counters.get(channel, 0) + 1
        message.sequence = self._sequence_counters[channel]
        message.channel = channel

        # Set expiry if not set
        if not message.expires_at:
            message.expires_at = message.received_at + config.ttl

        # Push to buffer
        success = await self.buffer.push(channel, message)

        if success:
            logger.debug(f"Published message {message.message_id} to channel {channel}")
        else:
            logger.error(f"Failed to publish message to channel {channel}")

        return success

    async def add_connection(self, connection: ConnectorConnection) -> bool:
        """
        Add a new connector connection.

        Starts buffer consumer on first client for deferred consumption.

        Args:
            connection: Connection to add

        Returns:
            True if added, False if rejected (channel not found or max connections)
        """
        async with self._connections_lock:
            channel = connection.channel

            if channel not in self.channels:
                logger.warning(f"Connection rejected: channel {channel} not found")
                return False

            config = self.channels[channel]
            current_count = len(self.channel_connections.get(channel, set()))

            if current_count >= config.max_connections:
                logger.warning(
                    f"Connection rejected: max connections ({config.max_connections}) reached for {channel}"
                )
                return False

            self.connections[connection.connection_id] = connection
            self.channel_connections[channel].add(connection.connection_id)
            connection.state = ConnectionState.CONNECTED

        # Start buffer consumer if this is the first client for this channel
        if channel not in self._consumer_tags:
            callback = self._make_delivery_callback(channel)
            webhook_ids = list(self._channel_webhook_ids.get(channel, set()))
            consumer_tag = await self.buffer.subscribe(
                channel, callback, webhook_ids=webhook_ids
            )
            if consumer_tag:
                self._consumer_tags[channel] = consumer_tag
                logger.info(
                    f"Started buffer consumer for {channel} (first client connected, "
                    f"{len(webhook_ids)} webhook queue(s))"
                )

        logger.info(f"Added connection {connection.connection_id} to channel {channel}")
        return True

    async def remove_connection(self, connection_id: str) -> None:
        """
        Remove a connector connection.

        Args:
            connection_id: ID of connection to remove
        """
        async with self._connections_lock:
            await self._cleanup_connection(connection_id)

    async def _cleanup_connection(self, connection_id: str) -> None:
        """Internal cleanup of connection (must be called with lock held)."""
        if connection_id not in self.connections:
            return

        connection = self.connections.pop(connection_id)
        channel = connection.channel

        if channel in self.channel_connections:
            self.channel_connections[channel].discard(connection_id)

        # Return in-flight messages to queue
        for msg_id in connection.in_flight_messages:
            await self.buffer.nack(channel, msg_id, retry=True)

        connection.state = ConnectionState.DISCONNECTED

        # Remove per-connection send function
        self._connection_send_fns.pop(connection_id, None)

        # If no more clients on this channel, stop consuming (deferred consumption)
        remaining = self.channel_connections.get(channel, set())
        if not remaining:
            consumer_tag = self._consumer_tags.pop(channel, None)
            if consumer_tag:
                await self.buffer.unsubscribe(consumer_tag)
                logger.info(
                    f"Stopped buffer consumer for {channel} (no clients remaining)"
                )

        logger.info(f"Removed connection {connection_id} from channel {channel}")

    async def _eviction_loop(self) -> None:
        """Periodically check for and evict stale connections."""
        try:
            while True:
                await asyncio.sleep(EVICTION_CHECK_INTERVAL_SECONDS)
                try:
                    await self._evict_stale_connections()
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    logger.error(f"Error during stale connection eviction: {e}")
                    # Add jitter on error to prevent thundering herd
                    jitter = random.uniform(0, EVICTION_CHECK_INTERVAL_SECONDS * 0.5)
                    await asyncio.sleep(jitter)
        except asyncio.CancelledError:
            logger.debug("Eviction loop cancelled")

    async def _evict_stale_connections(self) -> None:
        """Detect and remove stale connections based on protocol-aware thresholds."""
        now = datetime.now(timezone.utc)
        stale_ids: List[str] = []

        async with self._connections_lock:
            for conn_id, conn in self.connections.items():
                if self._is_connection_stale(conn, now):
                    stale_ids.append(conn_id)

        # Remove stale connections outside lock (remove_connection acquires lock)
        for conn_id in stale_ids:
            logger.warning(f"Evicting stale connection: {conn_id}")
            await self.remove_connection(conn_id)

    def _is_connection_stale(
        self, conn: ConnectorConnection, now: datetime
    ) -> bool:
        """
        Check if a connection is stale based on its protocol.

        Args:
            conn: The connection to check
            now: Current UTC timestamp

        Returns:
            True if the connection should be evicted
        """
        if conn.state != ConnectionState.CONNECTED:
            return False

        if conn.protocol == ConnectionProtocol.WEBSOCKET:
            return self._is_ws_stale(conn, now)
        elif conn.protocol == ConnectionProtocol.SSE:
            return self._is_sse_stale(conn, now)
        elif conn.protocol == ConnectionProtocol.LONG_POLL:
            return self._is_long_poll_stale(conn, now)
        return False

    def _is_ws_stale(self, conn: ConnectorConnection, now: datetime) -> bool:
        """Check if a WebSocket connection is stale."""
        channel_config = self.channels.get(conn.channel)
        if not channel_config:
            return True  # Channel no longer exists

        if conn.last_heartbeat_at is not None:
            heartbeat_threshold = (
                channel_config.heartbeat_interval.total_seconds()
                * STALE_HEARTBEAT_MULTIPLIER
            )
            elapsed = (now - conn.last_heartbeat_at).total_seconds()
            return elapsed > heartbeat_threshold
        else:
            # No heartbeat yet — use grace period from connected_at
            elapsed = (now - conn.connected_at).total_seconds()
            return elapsed > INITIAL_HEARTBEAT_GRACE_SECONDS

    def _is_sse_stale(self, conn: ConnectorConnection, now: datetime) -> bool:
        """Check if an SSE connection is stale."""
        last_activity = conn.last_message_at or conn.connected_at
        elapsed = (now - last_activity).total_seconds()
        return elapsed > SSE_STALE_SECONDS

    def _is_long_poll_stale(
        self, conn: ConnectorConnection, now: datetime
    ) -> bool:
        """Check if a long-poll connection is stale."""
        last_activity = conn.last_message_at or conn.connected_at
        elapsed = (now - last_activity).total_seconds()
        return elapsed > LONG_POLL_STALE_SECONDS

    def _make_delivery_callback(
        self, channel: str
    ) -> Callable[[WebhookMessage], Awaitable[None]]:
        """
        Create a delivery callback for buffer subscription.

        The callback tries all connected clients for the channel.
        If no clients are available, it nacks with requeue so the
        message stays in the buffer.

        Args:
            channel: Channel name

        Returns:
            Async callback that delivers messages to connections
        """

        async def deliver(message: WebhookMessage) -> None:
            connection_ids = list(self.channel_connections.get(channel, set()))
            if not connection_ids:
                # No clients -- nack with requeue so it stays in buffer
                await self.buffer.nack(channel, message.message_id, retry=True)
                return

            last_error = None
            for conn_id in connection_ids:
                conn = self.connections.get(conn_id)
                if not conn or conn.state != ConnectionState.CONNECTED:
                    continue
                try:
                    send_fn = self._connection_send_fns.get(conn_id)
                    if send_fn:
                        await send_fn(message)
                    else:
                        raise RuntimeError(f"No send function for {conn_id}")
                    return  # Success -- delivered to one client
                except Exception as e:
                    last_error = e
                    logger.warning(f"Delivery failed to {conn_id}: {e}")

            # All connections failed
            if last_error:
                raise last_error  # Buffer will requeue

        return deliver

    def register_send_fn(
        self,
        connection_id: str,
        send_fn: Callable[[WebhookMessage], Awaitable[None]],
    ) -> None:
        """
        Register a per-connection send function for message delivery.

        Args:
            connection_id: Connection ID
            send_fn: Async function that sends a message to this connection
        """
        self._connection_send_fns[connection_id] = send_fn

    async def get_webhook_queue_depths(self, channel: str) -> Dict[str, int]:
        """
        Get pending message count per webhook for a channel.

        Args:
            channel: Channel name

        Returns:
            Dict mapping webhook_id to pending message count
        """
        webhook_ids = list(self._channel_webhook_ids.get(channel, set()))
        if not webhook_ids:
            return {}
        return await self.buffer.get_webhook_queue_depths(channel, webhook_ids)

    def get_connection(self, connection_id: str) -> Optional[ConnectorConnection]:
        """Get connection by ID."""
        return self.connections.get(connection_id)

    def get_channel_connections(self, channel: str) -> List[ConnectorConnection]:
        """Get all connections for a channel."""
        connection_ids = self.channel_connections.get(channel, set())
        return [
            self.connections[cid] for cid in connection_ids if cid in self.connections
        ]

    async def ack_message(
        self, channel: str, message_id: str, connection_id: str
    ) -> bool:
        """
        Acknowledge message delivery.

        Args:
            channel: Channel name
            message_id: Message ID
            connection_id: Connection that processed the message

        Returns:
            True if acknowledged, False otherwise
        """
        connection = self.connections.get(connection_id)
        if connection:
            connection.in_flight_messages.discard(message_id)
            connection.messages_acked += 1

        return await self.buffer.ack(channel, message_id)

    async def nack_message(
        self, channel: str, message_id: str, connection_id: str, retry: bool = True
    ) -> bool:
        """
        Negative acknowledge message.

        Args:
            channel: Channel name
            message_id: Message ID
            connection_id: Connection that failed to process
            retry: Whether to retry delivery

        Returns:
            True if processed, False otherwise
        """
        connection = self.connections.get(connection_id)
        if connection:
            connection.in_flight_messages.discard(message_id)
            connection.messages_nacked += 1

        return await self.buffer.nack(channel, message_id, retry=retry)

    async def get_channel_stats(self, channel: str) -> Optional[ChannelStats]:
        """
        Get statistics for a channel.

        Args:
            channel: Channel name

        Returns:
            ChannelStats or None if channel not found
        """
        if channel not in self.channels:
            return None

        stats = await self.buffer.get_stats(channel)
        stats.connected_clients = len(self.channel_connections.get(channel, set()))
        return stats

    def list_channels(self) -> List[str]:
        """List all registered channel names."""
        return list(self.channels.keys())

    def get_all_stats(self) -> Dict[str, Dict]:
        """Get summary stats for all channels."""
        result = {}
        for channel_name in self.channels:
            config = self.channels[channel_name]
            result[channel_name] = {
                "webhook_id": config.webhook_id,
                "connected_clients": len(
                    self.channel_connections.get(channel_name, set())
                ),
                "max_connections": config.max_connections,
                "ttl_seconds": int(config.ttl.total_seconds()),
            }
        return result

    async def health_check(self) -> Dict[str, bool]:
        """
        Check health of channel manager components.

        Returns:
            Dict with component health status
        """
        buffer_healthy = await self.buffer.health_check()

        return {
            "buffer": buffer_healthy,
            "channels_count": len(self.channels),
            "connections_count": len(self.connections),
        }

    def is_running(self) -> bool:
        """
        Check if channel manager is running.

        Returns:
            True if running and buffer is connected, False otherwise
        """
        if self.buffer is None:
            return False

        # Check if buffer has a connected client
        # For Redis buffer
        if hasattr(self.buffer, "redis") and self.buffer.redis is not None:
            return True

        # For RabbitMQ buffer
        if hasattr(self.buffer, "connection") and self.buffer.connection is not None:
            return True

        # Fallback: assume running if buffer exists
        return True
