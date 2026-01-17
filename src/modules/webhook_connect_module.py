"""
Webhook Connect Module.

This module queues webhooks to a channel for consumption by
remote Local Connectors via the Streaming API.

Instead of processing webhooks directly (like other modules),
this module publishes them to an internal queue which is then
streamed to connected Local Connectors.
"""

import logging
from typing import Any, Dict
from datetime import datetime, timedelta, timezone

from src.modules.base import BaseModule
from src.webhook_connect.models import WebhookMessage

logger = logging.getLogger(__name__)


class WebhookConnectModule(BaseModule):
    """
    Module that queues webhooks to a channel for remote consumption.

    Configuration options:
        - channel: Channel name (required)
        - channel_token: Authentication token for connectors (required)
        - ttl_seconds: Message time-to-live in seconds (default: 86400)
        - max_queue_size: Maximum messages in queue (default: 10000)
        - max_connections: Max concurrent connectors (default: 10)

    Example configuration:
        {
            "webhook_id": {
                "data_type": "json",
                "module": "webhook_connect",
                "module-config": {
                    "channel": "stripe-payments",
                    "channel_token": "{$STRIPE_CHANNEL_TOKEN}",
                    "ttl_seconds": 86400
                },
                "hmac": { ... }
            }
        }
    """

    # Class-level channel manager reference (set by application startup)
    _channel_manager = None

    @classmethod
    def set_channel_manager(cls, channel_manager) -> None:
        """
        Set the channel manager instance.

        This should be called during application startup to inject
        the channel manager dependency.
        """
        cls._channel_manager = channel_manager

    @classmethod
    def get_channel_manager(cls):
        """Get the channel manager instance."""
        return cls._channel_manager

    def __init__(self, config: Dict[str, Any], pool_registry=None):
        """
        Initialize the WebhookConnectModule.

        Args:
            config: Webhook configuration including module-config
            pool_registry: Optional connection pool registry (not used by this module)
        """
        super().__init__(config, pool_registry)

        # Extract channel configuration
        self.channel_name = self.module_config.get("channel")
        self.channel_token = self.module_config.get("channel_token")
        self.ttl_seconds = self.module_config.get("ttl_seconds", 86400)
        self.max_queue_size = self.module_config.get("max_queue_size", 10000)
        self.max_connections = self.module_config.get("max_connections", 10)
        self.max_in_flight = self.module_config.get("max_in_flight", 100)

        # Get webhook_id from config (set by webhook handler as _webhook_id)
        self.webhook_id = config.get("_webhook_id") or config.get("webhook_id", "unknown")

        # Setup tracking
        self._setup_done = False

        # Validation
        if not self.channel_name:
            raise ValueError("WebhookConnectModule requires 'channel' in module-config")
        if not self.channel_token:
            raise ValueError("WebhookConnectModule requires 'channel_token' in module-config")

    async def setup(self) -> None:
        """
        Register channel with channel manager.

        This is called once when the webhook is first accessed.
        """
        channel_manager = self.get_channel_manager()
        if not channel_manager:
            logger.warning("ChannelManager not available, webhook_connect will not function")
            return

        # Register or update channel
        await channel_manager.register_channel(
            name=self.channel_name,
            webhook_id=self.webhook_id,
            token=self.channel_token,
            ttl=timedelta(seconds=self.ttl_seconds),
            max_queue_size=self.max_queue_size,
            max_connections=self.max_connections,
            max_in_flight=self.max_in_flight,
        )

        self._setup_done = True
        logger.info(
            f"WebhookConnectModule setup complete: channel={self.channel_name}, "
            f"webhook_id={self.webhook_id}, ttl={self.ttl_seconds}s"
        )

    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        """
        Queue webhook to channel for remote consumption.

        Args:
            payload: The webhook payload
            headers: The request headers

        Raises:
            Exception: If channel manager is not available or queue is full
        """
        # Lazy setup: register channel on first webhook
        if not self._setup_done:
            await self.setup()

        channel_manager = self.get_channel_manager()
        if not channel_manager:
            raise Exception("ChannelManager not available")

        # Create webhook message
        message = WebhookMessage(
            channel=self.channel_name,
            webhook_id=self.webhook_id,
            payload=payload,
            headers=headers,
            received_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=self.ttl_seconds),
            metadata={
                "source": "webhook_connect_module",
            }
        )

        # Publish to channel
        success = await channel_manager.publish(self.channel_name, message)

        if not success:
            raise Exception(f"Failed to queue message to channel {self.channel_name} (queue may be full)")

        logger.debug(
            f"Queued webhook to channel {self.channel_name}: "
            f"message_id={message.message_id}, sequence={message.sequence}"
        )

    async def teardown(self) -> None:
        """
        Cleanup resources.

        Note: We don't unregister the channel here because other webhooks
        might be using it, and the channel should persist across restarts.
        """
        pass

    def get_channel_info(self) -> Dict[str, Any]:
        """
        Get information about the configured channel.

        Returns:
            Dict with channel configuration
        """
        return {
            "channel": self.channel_name,
            "webhook_id": self.webhook_id,
            "ttl_seconds": self.ttl_seconds,
            "max_queue_size": self.max_queue_size,
            "max_connections": self.max_connections,
        }
