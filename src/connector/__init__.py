"""
Local Connector for Webhook Connect.

The Local Connector runs on the local network and receives webhooks
from the Cloud Receiver via WebSocket or SSE streaming.

Usage:
    # As a module
    python -m src.connector.main --config connector.json

    # Programmatically
    from src.connector import LocalConnector, ConnectorConfig

    config = ConnectorConfig.load("connector.json")
    connector = LocalConnector(config)
    await connector.start()
"""

# Only import config (no external dependencies)
from src.connector.config import ConnectorConfig, TargetConfig


# Lazy imports for components with external dependencies
def __getattr__(name):
    """Lazy import for components that require aiohttp."""
    if name in ("StreamClient", "WebSocketClient", "SSEClient", "create_client"):
        from src.connector.stream_client import (
            StreamClient,
            WebSocketClient,
            SSEClient,
            create_client,
        )

        return {
            "StreamClient": StreamClient,
            "WebSocketClient": WebSocketClient,
            "SSEClient": SSEClient,
            "create_client": create_client,
        }[name]
    elif name == "MessageProcessor":
        from src.connector.processor import MessageProcessor

        return MessageProcessor
    elif name == "ModuleProcessor":
        from src.connector.module_processor import ModuleProcessor

        return ModuleProcessor
    elif name == "LocalConnector":
        from src.connector.main import LocalConnector

        return LocalConnector
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "ConnectorConfig",
    "TargetConfig",
    "StreamClient",
    "WebSocketClient",
    "SSEClient",
    "create_client",
    "MessageProcessor",
    "ModuleProcessor",
    "LocalConnector",
]
