#!/usr/bin/env python3
"""
Local Connector for Webhook Connect.

This is the main entry point for the Local Connector service.
It connects to the Cloud Receiver and forwards webhooks to local targets.

Usage:
    python -m src.connector.main --config connector.json
    python -m src.connector.main --channel my-channel --token secret --cloud-url https://webhooks.example.com

Environment variables:
    CONNECTOR_CLOUD_URL: Cloud Receiver URL
    CONNECTOR_CHANNEL: Channel name
    CONNECTOR_TOKEN: Authentication token
    CONNECTOR_TARGET_URL: Default target URL
    CONNECTOR_PROTOCOL: websocket or sse
    CONNECTOR_LOG_LEVEL: DEBUG, INFO, WARNING, ERROR
"""

import argparse
import asyncio
import logging
import signal
import sys
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from src.connector.config import ConnectorConfig, TargetConfig
from src.connector.stream_client import create_client, ConnectionState
from src.connector.processor import MessageProcessor
from src.connector.module_processor import ModuleProcessor, load_json_config

logger = logging.getLogger(__name__)


class LocalConnector:
    """
    Local Connector service.

    Orchestrates the stream client and message processor to receive
    and deliver webhooks from the Cloud Receiver.
    """

    def __init__(self, config: ConnectorConfig):
        """
        Initialize the connector.

        Args:
            config: Connector configuration
        """
        self.config = config
        self.processor = None  # MessageProcessor or ModuleProcessor
        self.client = None
        self._running = False
        self._shutdown_event = asyncio.Event()
        self._start_time: Optional[datetime] = None

    async def start(self) -> None:
        """Start the connector."""
        if self._running:
            return

        self._running = True
        self._start_time = datetime.now(timezone.utc)
        self._shutdown_event.clear()

        logger.info("Starting Local Connector...")
        logger.info(f"  Channel: {self.config.channel}")
        logger.info(f"  Protocol: {self.config.protocol}")
        logger.info(f"  Cloud URL: {self.config.cloud_url}")
        logger.info(f"  Delivery mode: {self.config.delivery_mode}")

        # Create processor based on delivery mode
        if self.config.delivery_mode == "etcd":
            # Load config from etcd
            from src.etcd_config_provider import EtcdConfigProvider

            provider = EtcdConfigProvider(
                host=self.config.etcd_host,
                port=self.config.etcd_port,
                prefix=self.config.etcd_prefix,
                namespace=self.config.namespace,
            )
            # Initialize synchronously in executor (etcd3 is sync)
            import asyncio

            await asyncio.get_running_loop().run_in_executor(
                None, provider._sync_initialize
            )
            self._etcd_provider = provider

            ns = self.config.namespace or "default"
            webhooks = provider.get_all_webhook_configs(namespace=ns)
            connections = provider.get_all_connection_configs()
            logger.info(
                "Loaded %d webhook(s), %d connection(s) from etcd (namespace: %s)",
                len(webhooks),
                len(connections),
                ns,
            )
            self.processor = ModuleProcessor(
                config=self.config,
                webhooks=webhooks,
                connections=connections,
                ack_callback=self._send_ack,
                nack_callback=self._send_nack,
                config_provider=provider,
                config_namespace=ns,
            )
        elif self.config.delivery_mode == "module":
            webhooks = load_json_config(self.config.webhooks_config)
            connections = (
                load_json_config(self.config.connections_config)
                if self.config.connections_config
                else {}
            )
            self.processor = ModuleProcessor(
                config=self.config,
                webhooks=webhooks,
                connections=connections,
                ack_callback=self._send_ack,
                nack_callback=self._send_nack,
            )
        else:
            self.processor = MessageProcessor(
                config=self.config,
                ack_callback=self._send_ack,
                nack_callback=self._send_nack,
            )
        await self.processor.start()

        # Create stream client
        self.client = create_client(
            config=self.config,
            on_message=self._handle_message,
            on_connect=self._on_connect,
            on_disconnect=self._on_disconnect,
        )

        # Start client (this blocks until stop is called)
        try:
            await self.client.start()
        except asyncio.CancelledError:
            pass

        logger.info("Local Connector stopped")

    async def stop(self) -> None:
        """Stop the connector gracefully."""
        if not self._running:
            return

        logger.info("Stopping Local Connector...")
        self._running = False
        self._shutdown_event.set()

        if self.client:
            await self.client.stop()

        if self.processor:
            await self.processor.stop()

        # Shut down etcd provider if used
        if hasattr(self, "_etcd_provider") and self._etcd_provider:
            await self._etcd_provider.shutdown()

        logger.info("Local Connector shutdown complete")

    async def _handle_message(self, message: Dict[str, Any]) -> None:
        """Handle a received webhook message."""
        msg_type = message.get("type")

        if msg_type == "webhook":
            logger.debug(f"Received webhook: {message.get('message_id')}")
            await self.processor.process(message)
        else:
            logger.debug(f"Ignoring message type: {msg_type}")

    async def _send_ack(self, message_id: str) -> bool:
        """Send ACK through the stream client."""
        if self.client:
            return await self.client.send_ack(message_id)
        return False

    async def _send_nack(self, message_id: str, retry: bool) -> bool:
        """Send NACK through the stream client."""
        if self.client:
            return await self.client.send_nack(message_id, retry)
        return False

    async def _on_connect(self) -> None:
        """Called when connection is established."""
        logger.info(f"Connected to cloud (ID: {self.client.connection_id})")

    async def _on_disconnect(self, error: Optional[Exception]) -> None:
        """Called when connection is lost."""
        if error:
            logger.warning(f"Disconnected from cloud: {error}")
        else:
            logger.info("Disconnected from cloud")

    def get_status(self) -> Dict[str, Any]:
        """Get connector status."""
        return {
            "running": self._running,
            "connected": (
                self.client.state == ConnectionState.CONNECTED if self.client else False
            ),
            "connection_id": self.client.connection_id if self.client else None,
            "uptime_seconds": (
                (datetime.now(timezone.utc) - self._start_time).total_seconds()
                if self._start_time
                else 0
            ),
            "processor_stats": self.processor.get_stats() if self.processor else {},
            "config": self.config.to_dict(),
        }


def setup_logging(level: str = "INFO", format_str: Optional[str] = None) -> None:
    """Configure logging."""
    log_level = getattr(logging, level.upper(), logging.INFO)
    log_format = format_str or "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    logging.basicConfig(
        level=log_level, format=log_format, handlers=[logging.StreamHandler(sys.stdout)]
    )

    # Set aiohttp logging level
    logging.getLogger("aiohttp").setLevel(logging.WARNING)


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Local Connector for Webhook Connect",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Using configuration file
    %(prog)s --config connector.json

    # Using command line arguments
    %(prog)s --cloud-url https://webhooks.example.com \\
             --channel my-channel \\
             --token secret123 \\
             --target-url http://localhost:8000/webhook

    # With environment variables
    export CONNECTOR_CLOUD_URL=https://webhooks.example.com
    export CONNECTOR_CHANNEL=my-channel
    export CONNECTOR_TOKEN=secret123
    %(prog)s --target-url http://localhost:8000/webhook
        """,
    )

    parser.add_argument(
        "--config", "-c", help="Path to configuration file (JSON or YAML)"
    )

    parser.add_argument("--cloud-url", help="Cloud Receiver URL")

    parser.add_argument("--channel", help="Channel name to subscribe to")

    parser.add_argument("--token", help="Channel authentication token")

    parser.add_argument("--target-url", help="Default target URL for webhooks")

    parser.add_argument(
        "--protocol",
        choices=["websocket", "sse"],
        default="websocket",
        help="Connection protocol (default: websocket)",
    )

    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level (default: INFO)",
    )

    parser.add_argument("--connector-id", help="Unique identifier for this connector")

    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable SSL certificate verification",
    )

    # Module mode arguments
    parser.add_argument(
        "--webhooks-config",
        help="Path to webhooks.json for module mode (standard CWM format)",
    )

    parser.add_argument(
        "--connections-config",
        help="Path to connections.json for module mode (standard CWM format)",
    )

    return parser.parse_args()


def build_config(args: argparse.Namespace) -> ConnectorConfig:
    """Build configuration from arguments and environment."""
    # Start with file config if provided
    if args.config:
        config = ConnectorConfig.from_file(args.config)
    else:
        config = ConnectorConfig.from_env()

    # Override with command line arguments
    if args.cloud_url:
        config.cloud_url = args.cloud_url
    if args.channel:
        config.channel = args.channel
    if args.token:
        config.token = args.token
    if args.protocol:
        config.protocol = args.protocol
    if args.log_level:
        config.log_level = args.log_level
    if args.connector_id:
        config.connector_id = args.connector_id
    if args.no_verify_ssl:
        config.verify_ssl = False

    # Set default target if provided (HTTP mode)
    if args.target_url:
        config.default_target = TargetConfig(url=args.target_url)

    # Module mode overrides
    if args.webhooks_config:
        config.webhooks_config = args.webhooks_config
    if args.connections_config:
        config.connections_config = args.connections_config

    return config


async def main_async(connector: LocalConnector) -> None:
    """Async main function."""
    # Setup signal handlers
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def signal_handler():
        logger.info("Received shutdown signal")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, signal_handler)

    # Start connector in background
    connector_task = asyncio.create_task(connector.start())

    # Wait for shutdown signal
    await stop_event.wait()

    # Stop connector
    await connector.stop()

    # Cancel connector task if still running
    if not connector_task.done():
        connector_task.cancel()
        try:
            await connector_task
        except asyncio.CancelledError:
            pass


def main() -> int:
    """Main entry point."""
    args = parse_args()

    # Build configuration
    config = build_config(args)

    # Setup logging
    setup_logging(level=config.log_level, format_str=config.log_format)

    # Validate configuration
    errors = config.validate()
    if errors:
        logger.error("Configuration errors:")
        for error in errors:
            logger.error(f"  - {error}")
        return 1

    # Log startup banner
    banner = (
        "\n" + "=" * 60 + "\n"
        "\n"
        "    Webhook Connect - Local Connector\n"
        "=" * 60 + "\n"
        f"  Channel:   {config.channel}\n"
        f"  Protocol:  {config.protocol}\n"
        f"  Cloud URL: {config.cloud_url}\n"
        f"  Mode:      {config.delivery_mode}\n"
        "=" * 60 + "\n"
    )
    logger.info(banner)

    # Create and run connector
    connector = LocalConnector(config)

    try:
        asyncio.run(main_async(connector))
        return 0
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
