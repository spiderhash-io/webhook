"""
Configuration for Local Connector.

Supports loading configuration from:
- YAML/JSON files
- Environment variables
- Command line arguments
"""

import os
import json
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class TargetConfig:
    """Configuration for a webhook delivery target."""

    url: str
    method: str = "POST"
    headers: Dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 30.0
    retry_enabled: bool = True
    retry_max_attempts: int = 3
    retry_delay_seconds: float = 1.0
    retry_backoff_multiplier: float = 2.0


@dataclass
class ConnectorConfig:
    """
    Local Connector configuration.

    Configuration priority (highest to lowest):
    1. Environment variables (prefixed with CONNECTOR_)
    2. Configuration file (connector.json or connector.yaml)
    3. Default values

    Environment variables:
        CONNECTOR_CLOUD_URL: Cloud Receiver URL
        CONNECTOR_CHANNEL: Channel name
        CONNECTOR_TOKEN: Channel authentication token
        CONNECTOR_TARGET_URL: Default target URL for webhooks
        CONNECTOR_PROTOCOL: Connection protocol (websocket or sse)
        CONNECTOR_RECONNECT_DELAY: Seconds between reconnect attempts
        CONNECTOR_MAX_RECONNECT_DELAY: Maximum reconnect delay
        CONNECTOR_HEARTBEAT_TIMEOUT: Heartbeat timeout seconds
        CONNECTOR_LOG_LEVEL: Logging level (DEBUG, INFO, WARNING, ERROR)
    """

    # Cloud connection settings
    cloud_url: str = ""
    channel: str = ""
    token: str = ""

    # Connection settings
    protocol: str = "websocket"  # "websocket" or "sse"
    reconnect_delay: float = 1.0
    max_reconnect_delay: float = 60.0
    reconnect_backoff_multiplier: float = 2.0
    heartbeat_timeout: float = 60.0
    connection_timeout: float = 30.0

    # Processing settings
    max_concurrent_requests: int = 10
    ack_timeout: float = 30.0

    # Default target for webhooks (can be overridden per webhook_id)
    default_target: Optional[TargetConfig] = None

    # Target routing: webhook_id -> TargetConfig
    targets: Dict[str, TargetConfig] = field(default_factory=dict)

    # Logging
    log_level: str = "INFO"
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # TLS settings
    verify_ssl: bool = True
    ca_cert_path: Optional[str] = None
    client_cert_path: Optional[str] = None
    client_key_path: Optional[str] = None

    # Connector identification
    connector_id: Optional[str] = None

    @classmethod
    def from_file(cls, path: str) -> "ConnectorConfig":
        """Load configuration from a file."""
        file_path = Path(path)

        if not file_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {path}")

        with open(file_path, "r") as f:
            if file_path.suffix in [".yaml", ".yml"]:
                try:
                    import yaml

                    data = yaml.safe_load(f)
                except ImportError:
                    raise ImportError("PyYAML is required to load YAML config files")
            else:
                data = json.load(f)

        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ConnectorConfig":
        """Create configuration from a dictionary."""
        config = cls()

        # Simple fields
        simple_fields = [
            "cloud_url",
            "channel",
            "token",
            "protocol",
            "reconnect_delay",
            "max_reconnect_delay",
            "reconnect_backoff_multiplier",
            "heartbeat_timeout",
            "connection_timeout",
            "max_concurrent_requests",
            "ack_timeout",
            "log_level",
            "log_format",
            "verify_ssl",
            "ca_cert_path",
            "client_cert_path",
            "client_key_path",
            "connector_id",
        ]

        for field_name in simple_fields:
            if field_name in data:
                setattr(config, field_name, data[field_name])

        # Default target
        if "default_target" in data:
            config.default_target = TargetConfig(**data["default_target"])

        # Per-webhook targets
        if "targets" in data:
            config.targets = {}
            for webhook_id, target_data in data["targets"].items():
                config.targets[webhook_id] = TargetConfig(**target_data)

        return config

    @classmethod
    def from_env(cls) -> "ConnectorConfig":
        """Create configuration from environment variables."""
        config = cls()

        # Map environment variables to config fields
        env_mapping = {
            "CONNECTOR_CLOUD_URL": "cloud_url",
            "CONNECTOR_CHANNEL": "channel",
            "CONNECTOR_TOKEN": "token",
            "CONNECTOR_PROTOCOL": "protocol",
            "CONNECTOR_RECONNECT_DELAY": ("reconnect_delay", float),
            "CONNECTOR_MAX_RECONNECT_DELAY": ("max_reconnect_delay", float),
            "CONNECTOR_HEARTBEAT_TIMEOUT": ("heartbeat_timeout", float),
            "CONNECTOR_CONNECTION_TIMEOUT": ("connection_timeout", float),
            "CONNECTOR_MAX_CONCURRENT_REQUESTS": ("max_concurrent_requests", int),
            "CONNECTOR_ACK_TIMEOUT": ("ack_timeout", float),
            "CONNECTOR_LOG_LEVEL": "log_level",
            "CONNECTOR_VERIFY_SSL": ("verify_ssl", lambda x: x.lower() == "true"),
            "CONNECTOR_CA_CERT_PATH": "ca_cert_path",
            "CONNECTOR_CLIENT_CERT_PATH": "client_cert_path",
            "CONNECTOR_CLIENT_KEY_PATH": "client_key_path",
            "CONNECTOR_ID": "connector_id",
        }

        for env_var, field_info in env_mapping.items():
            value = os.environ.get(env_var)
            if value:
                if isinstance(field_info, tuple):
                    field_name, converter = field_info
                    setattr(config, field_name, converter(value))
                else:
                    setattr(config, field_info, value)

        # Default target from environment
        target_url = os.environ.get("CONNECTOR_TARGET_URL")
        if target_url:
            config.default_target = TargetConfig(
                url=target_url,
                method=os.environ.get("CONNECTOR_TARGET_METHOD", "POST"),
                timeout_seconds=float(os.environ.get("CONNECTOR_TARGET_TIMEOUT", "30")),
            )

        return config

    @classmethod
    def load(cls, config_path: Optional[str] = None) -> "ConnectorConfig":
        """
        Load configuration with proper precedence.

        1. Start with defaults
        2. Override with file config (if provided)
        3. Override with environment variables
        """
        # Start with defaults
        config = cls()

        # Load from file if provided
        if config_path:
            file_config = cls.from_file(config_path)
            config = file_config

        # Override with environment variables
        env_config = cls.from_env()

        # Merge environment overrides
        for field_name in [
            "cloud_url",
            "channel",
            "token",
            "protocol",
            "reconnect_delay",
            "max_reconnect_delay",
            "heartbeat_timeout",
            "connection_timeout",
            "max_concurrent_requests",
            "ack_timeout",
            "log_level",
            "verify_ssl",
            "connector_id",
        ]:
            env_value = getattr(env_config, field_name)
            # Only override if env value is different from default
            default_value = getattr(cls(), field_name)
            if env_value != default_value:
                setattr(config, field_name, env_value)

        # Override default target if set in env
        if env_config.default_target:
            config.default_target = env_config.default_target

        return config

    def validate(self) -> List[str]:
        """
        Validate configuration.

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        if not self.cloud_url:
            errors.append("cloud_url is required")

        if not self.channel:
            errors.append("channel is required")

        if not self.token:
            errors.append("token is required")

        if self.protocol not in ["websocket", "sse"]:
            errors.append(
                f"protocol must be 'websocket' or 'sse', got '{self.protocol}'"
            )

        if not self.default_target and not self.targets:
            errors.append("Either default_target or targets must be configured")

        if self.reconnect_delay <= 0:
            errors.append("reconnect_delay must be positive")

        if self.max_reconnect_delay < self.reconnect_delay:
            errors.append("max_reconnect_delay must be >= reconnect_delay")

        if self.heartbeat_timeout <= 0:
            errors.append("heartbeat_timeout must be positive")

        return errors

    def get_target(self, webhook_id: str) -> Optional[TargetConfig]:
        """Get target configuration for a webhook ID."""
        return self.targets.get(webhook_id, self.default_target)

    def get_stream_url(self) -> str:
        """Get the full streaming URL for the configured channel."""
        base_url = self.cloud_url.rstrip("/")

        if self.protocol == "websocket":
            # Convert http(s) to ws(s)
            if base_url.startswith("https://"):
                ws_url = "wss://" + base_url[8:]
            elif base_url.startswith("http://"):
                ws_url = "ws://" + base_url[7:]
            else:
                ws_url = base_url
            return f"{ws_url}/connect/stream/{self.channel}"
        else:
            return f"{base_url}/connect/stream/{self.channel}/sse"

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary (excluding sensitive data)."""
        return {
            "cloud_url": self.cloud_url,
            "channel": self.channel,
            "protocol": self.protocol,
            "reconnect_delay": self.reconnect_delay,
            "max_reconnect_delay": self.max_reconnect_delay,
            "heartbeat_timeout": self.heartbeat_timeout,
            "connection_timeout": self.connection_timeout,
            "max_concurrent_requests": self.max_concurrent_requests,
            "ack_timeout": self.ack_timeout,
            "log_level": self.log_level,
            "verify_ssl": self.verify_ssl,
            "connector_id": self.connector_id,
            "targets_count": len(self.targets),
            "has_default_target": self.default_target is not None,
        }
