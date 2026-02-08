"""
File-based configuration provider.

Wraps the existing JSON file loading logic (webhooks.json, connections.json)
behind the ConfigProvider interface. This is the default provider when
CONFIG_BACKEND=file (or unset).

Namespace parameter is accepted but ignored — file provider uses a single
flat namespace, preserving full backward compatibility.
"""

import json
import logging
import os
from typing import Any, Dict, Optional

from src.config_provider import ConfigProvider
from src.utils import load_env_vars, sanitize_error_message

logger = logging.getLogger(__name__)


class FileConfigProvider(ConfigProvider):
    """
    File-based configuration provider.

    Loads webhooks and connections from JSON files on disk.
    Supports environment variable substitution via load_env_vars().
    """

    def __init__(
        self,
        webhook_config_file: str = "webhooks.json",
        connection_config_file: str = "connections.json",
    ):
        """
        Initialize file config provider.

        Args:
            webhook_config_file: Path to webhooks.json file.
            connection_config_file: Path to connections.json file.
        """
        if not isinstance(webhook_config_file, str):
            raise TypeError("webhook_config_file must be a string")
        if not isinstance(connection_config_file, str):
            raise TypeError("connection_config_file must be a string")

        self.webhook_config_file = webhook_config_file
        self.connection_config_file = connection_config_file
        self._webhook_config: Dict[str, Any] = {}
        self._connection_config: Dict[str, Any] = {}
        self._initialized = False

    async def initialize(self) -> None:
        """Load initial configuration from files."""
        self._webhook_config = self._load_webhook_config()
        self._connection_config = self._load_connection_config()
        self._initialized = True
        logger.info(
            "FileConfigProvider initialized: %d webhook(s), %d connection(s)",
            len(self._webhook_config),
            len(self._connection_config),
        )

    async def shutdown(self) -> None:
        """No-op for file provider (no connections to close)."""
        self._initialized = False

    def get_webhook_config(
        self, webhook_id: str, namespace: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Get webhook config by ID. Namespace is ignored for file provider."""
        return self._webhook_config.get(webhook_id)

    def get_all_webhook_configs(
        self, namespace: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get all webhook configs. Namespace is ignored for file provider."""
        return dict(self._webhook_config)

    def get_connection_config(self, conn_name: str) -> Optional[Dict[str, Any]]:
        """Get connection config by name."""
        return self._connection_config.get(conn_name)

    def get_all_connection_configs(self) -> Dict[str, Any]:
        """Get all connection configs."""
        return dict(self._connection_config)

    def get_status(self) -> Dict[str, Any]:
        """Get file provider status."""
        return {
            "backend": "file",
            "initialized": self._initialized,
            "webhook_config_file": self.webhook_config_file,
            "connection_config_file": self.connection_config_file,
            "webhooks_count": len(self._webhook_config),
            "connections_count": len(self._connection_config),
        }

    def _load_webhook_config(self) -> Dict[str, Any]:
        """Load webhook config from JSON file with env var substitution."""
        if not os.path.exists(self.webhook_config_file):
            logger.info(
                "webhooks.json not found at '%s'. Using default logging webhook.",
                self.webhook_config_file,
            )
            return {
                "default": {
                    "data_type": "json",
                    "module": "log",
                    "module-config": {
                        "pretty_print": True,
                        "redact_sensitive": True,
                    },
                }
            }

        with open(self.webhook_config_file, "r") as f:
            config = json.load(f)

        config = load_env_vars(config)
        return config

    def _load_connection_config(self) -> Dict[str, Any]:
        """Load connection config from JSON file with env var substitution."""
        if not os.path.exists(self.connection_config_file):
            logger.info(
                "connections.json not found at '%s'. No connections configured.",
                self.connection_config_file,
            )
            return {}

        with open(self.connection_config_file, "r") as f:
            config = json.load(f)

        config = load_env_vars(config)
        return config

    def reload_webhooks(self) -> Dict[str, Any]:
        """
        Reload webhook config from file.

        Returns:
            The newly loaded webhook config dict.
        """
        self._webhook_config = self._load_webhook_config()
        return self._webhook_config

    def reload_connections(self) -> Dict[str, Any]:
        """
        Reload connection config from file.

        Returns:
            The newly loaded connection config dict.
        """
        self._connection_config = self._load_connection_config()
        return self._connection_config
