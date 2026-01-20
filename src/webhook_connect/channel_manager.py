"""
Channel Manager for Webhook Connect.

Manages channels, connections, and message routing between
the Cloud Receiver and Local Connectors.
"""

import asyncio
import json
import logging
import secrets
from typing import Dict, Optional, Set, List
from datetime import datetime, timedelta, timezone

from src.webhook_connect.models import (
    WebhookMessage,
    ChannelConfig,
    ConnectorConnection,
    ChannelStats,
    ConnectionState,
    MessageState,
)
from src.webhook_connect.buffer.interface import MessageBufferInterface

logger = logging.getLogger(__name__)


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

    async def start(self) -> None:
        """Start the channel manager and connect to buffer."""
        await self.buffer.connect()
        logger.info("ChannelManager started")

    async def stop(self) -> None:
        """Stop the channel manager and cleanup."""
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

        # Ensure channel exists in buffer
        await self.buffer.ensure_channel(name, int(ttl.total_seconds()))

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

        # Delete channel from buffer
        await self.buffer.delete_channel(name)

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
        logger.info(f"Removed connection {connection_id} from channel {channel}")

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
