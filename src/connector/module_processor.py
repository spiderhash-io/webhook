"""
Module Processor for Local Connector.

Dispatches webhook messages to internal modules (log, kafka, save_to_disk, etc.)
using the same ModuleRegistry and ChainProcessor as the main webhook processor.

This enables the connector to use the standard webhooks.json + connections.json
config format instead of being limited to HTTP forwarding.
"""

import asyncio
import copy
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, Optional, Callable, Awaitable

from src.connector.config import ConnectorConfig
from src.config_provider import ConfigProvider

logger = logging.getLogger(__name__)


@dataclass
class ModuleProcessingStats:
    """Statistics for module-mode processing."""

    messages_delivered: int = 0
    messages_failed: int = 0
    messages_skipped: int = 0


def load_json_config(path: str) -> Dict[str, Any]:
    """
    Load a JSON configuration file.

    Args:
        path: Path to the JSON file

    Returns:
        Parsed dictionary

    Raises:
        FileNotFoundError: If file does not exist
        json.JSONDecodeError: If file is not valid JSON
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")

    with open(file_path, "r") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object in {path}, got {type(data).__name__}")

    return data


class ModuleProcessor:
    """
    Processes webhook messages by dispatching to internal modules.

    Replaces MessageProcessor when the connector is in module mode.
    Uses the same ModuleRegistry and ChainProcessor as the main webhook
    processor, enabling reuse of all output modules (log, kafka, save_to_disk,
    postgresql, etc.) with the standard webhooks.json config format.

    The webhook_id from the cloud message maps to the key in webhooks.json.
    Auth fields (authorization, data_type, rate_limit, etc.) are ignored
    since authentication is already handled on the cloud side.
    """

    def __init__(
        self,
        config: ConnectorConfig,
        webhooks: Dict[str, Any],
        connections: Dict[str, Any],
        ack_callback: Callable[[str], Awaitable[bool]],
        nack_callback: Callable[[str, bool], Awaitable[bool]],
        config_provider: Optional[ConfigProvider] = None,
        config_namespace: Optional[str] = None,
    ):
        self.config = config
        self.webhooks = webhooks
        self.connections = connections
        self.ack_callback = ack_callback
        self.nack_callback = nack_callback
        self._config_provider = config_provider
        self._config_namespace = config_namespace

        self._max_concurrent = config.max_concurrent_requests
        self._semaphore = None  # Lazy init to avoid event loop requirement in __init__
        self._stats = ModuleProcessingStats()
        self._running = False
        self._in_flight: Dict[str, asyncio.Task] = {}

        # Lazy imports to avoid circular dependencies and import errors
        # when module dependencies aren't installed
        self._pool_registry = None
        self._ModuleRegistry = None
        self._ChainProcessor = None

    def _resolve_webhook_config(self, webhook_id: str) -> Optional[Dict[str, Any]]:
        """Look up webhook config from live provider or static dict."""
        if self._config_provider:
            return self._config_provider.get_webhook_config(
                webhook_id, namespace=self._config_namespace
            )
        return self.webhooks.get(webhook_id)

    def _resolve_connection_config(self, conn_name: str) -> Optional[Dict[str, Any]]:
        """Look up connection config from live provider or static dict."""
        if self._config_provider:
            return self._config_provider.get_connection_config(conn_name)
        return self.connections.get(conn_name)

    def _resolve_all_connections(self) -> Dict[str, Any]:
        """Get all connection configs from live provider or static dict."""
        if self._config_provider:
            return self._config_provider.get_all_connection_configs()
        return self.connections

    def _get_pool_registry(self):
        if self._pool_registry is None:
            from src.connection_pool_registry import ConnectionPoolRegistry

            self._pool_registry = ConnectionPoolRegistry()
        return self._pool_registry

    def _get_module_registry(self):
        if self._ModuleRegistry is None:
            from src.modules.registry import ModuleRegistry

            self._ModuleRegistry = ModuleRegistry
        return self._ModuleRegistry

    def _get_chain_processor_class(self):
        if self._ChainProcessor is None:
            from src.chain_processor import ChainProcessor

            self._ChainProcessor = ChainProcessor
        return self._ChainProcessor

    async def start(self) -> None:
        """Start the module processor."""
        if self._running:
            return

        self._semaphore = asyncio.Semaphore(self._max_concurrent)
        self._running = True
        logger.info(
            f"Module processor started "
            f"(webhooks={len(self.webhooks)}, connections={len(self.connections)})"
        )

    async def stop(self) -> None:
        """Stop the module processor and cleanup."""
        self._running = False

        # Cancel all in-flight tasks
        for message_id, task in list(self._in_flight.items()):
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        self._in_flight.clear()

        # Close all connection pools
        pool_registry = self._pool_registry
        if pool_registry is not None:
            await pool_registry.close_all_pools()

        logger.info("Module processor stopped")

    async def process(self, message: Dict[str, Any]) -> None:
        """
        Process a received webhook message by dispatching to internal modules.

        Args:
            message: The webhook message data from stream
        """
        if not self._running:
            logger.warning("Module processor not running, ignoring message")
            return

        message_id = message.get("message_id")
        webhook_id = message.get("webhook_id")

        if not message_id:
            logger.error("Message missing message_id")
            return

        if not webhook_id:
            logger.error(f"Message {message_id} missing webhook_id")
            await self.nack_callback(message_id, False)
            return

        # Look up webhook config by webhook_id (live from provider if available)
        webhook_config = self._resolve_webhook_config(webhook_id)
        if not webhook_config:
            logger.error(
                f"No webhook config for webhook_id '{webhook_id}' in webhooks.json"
            )
            self._stats.messages_skipped += 1
            await self.nack_callback(message_id, False)  # no retry - config error
            return

        # Start processing task
        task = asyncio.create_task(
            self._process_message(message_id, webhook_id, webhook_config, message)
        )
        self._in_flight[message_id] = task

    async def _process_message(
        self,
        message_id: str,
        webhook_id: str,
        webhook_config: Dict[str, Any],
        message: Dict[str, Any],
    ) -> None:
        """Process a single message with semaphore and error handling."""
        try:
            async with self._semaphore:
                payload = message.get("payload")
                headers = message.get("headers", {})

                chain = webhook_config.get("chain")
                if chain:
                    await self._process_chain(
                        webhook_id, webhook_config, payload, headers
                    )
                else:
                    await self._process_module(
                        webhook_id, webhook_config, payload, headers
                    )

                await self.ack_callback(message_id)
                self._stats.messages_delivered += 1
                logger.debug(f"Delivered {message_id} via module mode (webhook={webhook_id})")

        except asyncio.CancelledError:
            logger.info(f"Processing cancelled for {message_id}")
            raise
        except Exception as e:
            logger.error(f"Module processing failed for {message_id}: {e}")
            self._stats.messages_failed += 1
            await self.nack_callback(message_id, True)  # retry
        finally:
            self._in_flight.pop(message_id, None)

    async def _process_module(
        self,
        webhook_id: str,
        webhook_config: Dict[str, Any],
        payload: Any,
        headers: Dict[str, str],
    ) -> None:
        """Dispatch to a single module — mirrors webhook.py single-module dispatch."""
        module_name = webhook_config.get("module")
        if not module_name:
            raise ValueError(f"No 'module' specified in config for webhook '{webhook_id}'")

        if not isinstance(module_name, str):
            raise ValueError(f"Module name must be a string for webhook '{webhook_id}'")

        ModuleRegistry = self._get_module_registry()
        module_class = ModuleRegistry.get(module_name)

        # Build module config with webhook_id
        module_config = {**webhook_config, "_webhook_id": webhook_id}

        # Inject connection_details if connection is specified
        connection_name = webhook_config.get("connection")
        if connection_name:
            conn_cfg = self._resolve_connection_config(connection_name)
            if conn_cfg:
                try:
                    connection_details = copy.deepcopy(conn_cfg)
                except (RecursionError, MemoryError):
                    connection_details = dict(conn_cfg)
                module_config["connection_details"] = connection_details

        pool_registry = self._get_pool_registry()
        module = module_class(module_config, pool_registry=pool_registry)

        try:
            await module.process(payload, headers)
        finally:
            await module.teardown()

    async def _process_chain(
        self,
        webhook_id: str,
        webhook_config: Dict[str, Any],
        payload: Any,
        headers: Dict[str, str],
    ) -> None:
        """Dispatch to chain — mirrors webhook.py chain dispatch."""
        chain = webhook_config["chain"]
        chain_config = webhook_config.get("chain-config", {})

        webhook_config_with_id = {**webhook_config, "_webhook_id": webhook_id}

        ChainProcessor = self._get_chain_processor_class()
        pool_registry = self._get_pool_registry()

        processor = ChainProcessor(
            chain=chain,
            chain_config=chain_config,
            webhook_config=webhook_config_with_id,
            pool_registry=pool_registry,
            connection_config=self._resolve_all_connections(),
        )

        results = await processor.execute(payload, headers)

        # Check if any module failed
        failed = [r for r in results if not r.success]
        if failed:
            failed_names = ", ".join(r.module_name for r in failed)
            raise RuntimeError(
                f"Chain execution for webhook '{webhook_id}' had failures: {failed_names}"
            )

    def get_stats(self) -> Dict[str, Any]:
        """Get processing statistics."""
        return {
            "messages_delivered": self._stats.messages_delivered,
            "messages_failed": self._stats.messages_failed,
            "messages_skipped": self._stats.messages_skipped,
            "in_flight_count": len(self._in_flight),
            "running": self._running,
            "webhooks_count": len(self.webhooks),
            "connections_count": len(self.connections),
        }

    @property
    def in_flight_count(self) -> int:
        """Number of messages currently being processed."""
        return len(self._in_flight)
