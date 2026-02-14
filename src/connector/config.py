"""
Configuration for Local Connector.

Supports loading configuration from:
- YAML/JSON files
- Environment variables
- Command line arguments
"""

import os
import re
import json
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from pathlib import Path
from urllib.parse import quote

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

    # Module mode: path to webhooks.json (standard CWM format)
    webhooks_config: Optional[str] = None
    # Module mode: path to connections.json (standard CWM format)
    connections_config: Optional[str] = None

    # etcd config backend (alternative to webhooks_config/connections_config files)
    etcd_host: Optional[str] = None
    etcd_port: int = 2379
    etcd_prefix: str = "/cwm/"
    namespace: Optional[str] = None

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
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict, got {type(data).__name__}")

        config = cls()

        # Field name -> expected type(s) for validation
        _FIELD_TYPES: Dict[str, type] = {
            "cloud_url": str,
            "channel": str,
            "token": str,
            "protocol": str,
            "reconnect_delay": (int, float),
            "max_reconnect_delay": (int, float),
            "reconnect_backoff_multiplier": (int, float),
            "heartbeat_timeout": (int, float),
            "connection_timeout": (int, float),
            "max_concurrent_requests": int,
            "ack_timeout": (int, float),
            "log_level": str,
            "log_format": str,
            "verify_ssl": bool,
            "ca_cert_path": str,
            "client_cert_path": str,
            "client_key_path": str,
            "connector_id": str,
            "webhooks_config": str,
            "connections_config": str,
            "etcd_host": str,
            "etcd_port": int,
            "etcd_prefix": str,
            "namespace": str,
        }

        for field_name, expected_type in _FIELD_TYPES.items():
            if field_name in data:
                value = data[field_name]
                if value is not None and not isinstance(value, expected_type):
                    raise TypeError(
                        f"Config field '{field_name}' expected {expected_type}, "
                        f"got {type(value).__name__}"
                    )
                setattr(config, field_name, value)

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
            "CONNECTOR_WEBHOOKS_CONFIG": "webhooks_config",
            "CONNECTOR_CONNECTIONS_CONFIG": "connections_config",
            "CONNECTOR_ETCD_HOST": "etcd_host",
            "CONNECTOR_ETCD_PORT": ("etcd_port", int),
            "CONNECTOR_ETCD_PREFIX": "etcd_prefix",
            "CONNECTOR_NAMESPACE": "namespace",
        }

        config._env_fields: set = set()
        for env_var, field_info in env_mapping.items():
            value = os.environ.get(env_var)
            if value:
                if isinstance(field_info, tuple):
                    field_name, converter = field_info
                    setattr(config, field_name, converter(value))
                else:
                    field_name = field_info
                    setattr(config, field_name, value)
                config._env_fields.add(field_name)

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

        # Merge environment overrides (only fields actually set via env vars)
        env_fields = getattr(env_config, "_env_fields", set())
        for field_name in env_fields:
            setattr(config, field_name, getattr(env_config, field_name))

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
        elif not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$', self.channel):
            errors.append(
                "channel must contain only alphanumeric characters, "
                "dots, hyphens, and underscores"
            )

        if not self.token:
            errors.append("token is required")

        if self.protocol not in ["websocket", "sse", "long_poll"]:
            errors.append(
                f"protocol must be 'websocket', 'sse', or 'long_poll', got '{self.protocol}'"
            )

        has_http_mode = self.default_target is not None or bool(self.targets)
        has_module_mode = bool(self.webhooks_config)
        has_etcd_mode = bool(self.etcd_host)
        if not has_http_mode and not has_module_mode and not has_etcd_mode:
            errors.append(
                "Either default_target/targets, webhooks_config, or etcd_host must be configured"
            )
        modes_count = sum([has_http_mode, has_module_mode, has_etcd_mode])
        if modes_count > 1:
            errors.append(
                "Only one delivery mode allowed: HTTP targets, webhooks_config, or etcd_host"
            )

        if self.reconnect_delay <= 0:
            errors.append("reconnect_delay must be positive")

        if self.max_reconnect_delay < self.reconnect_delay:
            errors.append("max_reconnect_delay must be >= reconnect_delay")

        if self.heartbeat_timeout <= 0:
            errors.append("heartbeat_timeout must be positive")

        return errors

    @property
    def delivery_mode(self) -> str:
        """Return 'module', 'etcd', or 'http' based on config."""
        if self.etcd_host:
            return "etcd"
        if self.webhooks_config:
            return "module"
        return "http"

    def get_target(self, webhook_id: str) -> Optional[TargetConfig]:
        """Get target configuration for a webhook ID."""
        return self.targets.get(webhook_id, self.default_target)

    def get_stream_url(self) -> str:
        """Get the full streaming URL for the configured channel."""
        # SECURITY: Validate channel name to prevent path traversal attacks.
        # Defence-in-depth — validate() also checks this, but get_stream_url()
        # must be safe even if called independently.
        if not self.channel or not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$', self.channel):
            raise ValueError(
                f"Invalid channel name: must be alphanumeric with dots, hyphens, underscores"
            )
        if ".." in self.channel:
            raise ValueError("Channel name must not contain path traversal sequences")

        base_url = self.cloud_url.rstrip("/")
        safe_channel = quote(self.channel, safe="")

        if self.protocol == "websocket":
            # Convert http(s) to ws(s)
            if base_url.startswith("https://"):
                ws_url = "wss://" + base_url[8:]
            elif base_url.startswith("http://"):
                ws_url = "ws://" + base_url[7:]
            else:
                ws_url = base_url
            return f"{ws_url}/connect/stream/{safe_channel}"
        elif self.protocol == "sse":
            return f"{base_url}/connect/stream/{safe_channel}/sse"
        elif self.protocol == "long_poll":
            return f"{base_url}/connect/stream/{safe_channel}/poll"
        else:
            # Should not reach here due to validation, but fallback to SSE
            raise ValueError(f"Unknown protocol: {self.protocol}")

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
            "delivery_mode": self.delivery_mode,
            "targets_count": len(self.targets),
            "has_default_target": self.default_target is not None,
            "has_webhooks_config": self.webhooks_config is not None,
            "has_etcd_config": self.etcd_host is not None,
            "namespace": self.namespace,
        }
