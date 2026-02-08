"""
Abstract base class for configuration providers.

ConfigProvider defines a read-only interface for accessing webhook and
connection configurations. Implementations can back this with files (default),
etcd, or other distributed stores.

The app only reads configuration through this interface — it never writes.
Users manage their config store directly (e.g., editing files, using etcdctl).
"""

import logging
from abc import ABC, abstractmethod
from typing import Any, Callable, Coroutine, Dict, List, Optional

logger = logging.getLogger(__name__)

# Type alias for config change callbacks
ConfigChangeCallback = Callable[[str, str, Optional[Dict[str, Any]]], Coroutine]


class ConfigProvider(ABC):
    """
    Abstract configuration provider interface.

    All config access in the app goes through this interface.
    Implementations must be safe for concurrent reads from async code.
    """

    @abstractmethod
    async def initialize(self) -> None:
        """
        Initialize the provider (load initial data, start watchers, etc.).

        Raises:
            Exception: If initialization fails critically.
        """

    @abstractmethod
    async def shutdown(self) -> None:
        """Clean up resources (close connections, stop watchers)."""

    @abstractmethod
    def get_webhook_config(
        self, webhook_id: str, namespace: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Get a single webhook's configuration.

        Args:
            webhook_id: The webhook identifier.
            namespace: Optional namespace scope. Ignored by file provider.

        Returns:
            Webhook config dict, or None if not found.
        """

    @abstractmethod
    def get_all_webhook_configs(
        self, namespace: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get all webhook configurations.

        Args:
            namespace: Optional namespace scope. Ignored by file provider.

        Returns:
            Dict mapping webhook_id -> config dict.
        """

    @abstractmethod
    def get_connection_config(self, conn_name: str) -> Optional[Dict[str, Any]]:
        """
        Get a single connection's configuration (always global).

        Args:
            conn_name: The connection name.

        Returns:
            Connection config dict, or None if not found.
        """

    @abstractmethod
    def get_all_connection_configs(self) -> Dict[str, Any]:
        """
        Get all connection configurations (always global).

        Returns:
            Dict mapping connection_name -> config dict.
        """

    @abstractmethod
    def get_status(self) -> Dict[str, Any]:
        """
        Get provider health/status information.

        Returns:
            Dict with provider-specific status fields.
        """

    def on_config_change(self, callback: ConfigChangeCallback) -> None:
        """
        Register a callback for config change notifications.

        The callback signature is:
            async callback(event_type: str, key: str, config: Optional[dict])

        Where event_type is "put" or "delete", key identifies the changed item,
        and config is the new value (None for deletes).

        Default implementation is a no-op (file provider doesn't push changes).

        Args:
            callback: Async callable to invoke on changes.
        """
