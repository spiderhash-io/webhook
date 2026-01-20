"""
ZeroMQ module for publishing webhook payloads to ZeroMQ sockets.
"""

import json
import re
import asyncio
import ipaddress
from typing import Any, Dict, Optional
from src.modules.base import BaseModule
from src.utils import sanitize_error_message

try:
    import zmq
    import zmq.asyncio

    ZMQ_AVAILABLE = True
except ImportError:
    ZMQ_AVAILABLE = False


class ZeroMQModule(BaseModule):
    """Module for publishing webhook payloads to ZeroMQ sockets."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        if not ZMQ_AVAILABLE:
            raise ImportError(
                "pyzmq library is required for ZeroMQ module. Install with: pip install pyzmq"
            )

        self.socket: Optional[zmq.asyncio.Socket] = None
        self.context: Optional[zmq.asyncio.Context] = None

        # Validate endpoint during initialization
        raw_endpoint = self.module_config.get("endpoint")
        if raw_endpoint is not None:
            self._validated_endpoint = self._validate_endpoint(raw_endpoint)
        else:
            self._validated_endpoint = None

        # Validate socket type
        self.socket_type = self.module_config.get("socket_type", "PUB").upper()
        self._validate_socket_type(self.socket_type)

    def _validate_endpoint(self, endpoint: str) -> str:
        """
        Validate ZeroMQ endpoint to prevent SSRF and injection.

        Args:
            endpoint: The ZeroMQ endpoint (e.g., "tcp://localhost:5555")

        Returns:
            Validated endpoint

        Raises:
            ValueError: If endpoint is invalid or contains dangerous patterns
        """
        if not endpoint or not isinstance(endpoint, str):
            raise ValueError("Endpoint must be a non-empty string")

        # SECURITY: Reject null bytes and control characters FIRST (before stripping)
        # Block all control characters except tab (which might be needed for some protocols)
        # Newlines and carriage returns are dangerous and should be blocked
        if "\x00" in endpoint or any(ord(c) < 32 and c != "\t" for c in endpoint):
            raise ValueError("Endpoint contains forbidden control characters")

        endpoint = endpoint.strip()

        if not endpoint:
            raise ValueError("Endpoint cannot be empty")

        # Maximum length to prevent DoS
        MAX_ENDPOINT_LENGTH = 512
        if len(endpoint) > MAX_ENDPOINT_LENGTH:
            raise ValueError(
                f"Endpoint too long: {len(endpoint)} characters (max: {MAX_ENDPOINT_LENGTH})"
            )

        # SECURITY: Only allow safe ZeroMQ transport protocols
        # Reject dangerous schemes
        dangerous_schemes = [
            "file://",
            "gopher://",
            "javascript:",
            "data:",
            "vbscript:",
        ]
        endpoint_lower = endpoint.lower()
        for scheme in dangerous_schemes:
            if endpoint_lower.startswith(scheme):
                raise ValueError(f"Endpoint contains dangerous scheme: {scheme}")

        # Only allow safe ZeroMQ transports
        allowed_schemes = ["tcp://", "ipc://", "inproc://"]
        if not any(endpoint_lower.startswith(scheme) for scheme in allowed_schemes):
            raise ValueError(
                f"Endpoint must use one of the allowed transports: {', '.join(allowed_schemes)}"
            )

        # For TCP endpoints, validate host and port
        if endpoint_lower.startswith("tcp://"):
            # Extract host:port
            try:
                parts = endpoint.split("://", 1)[1]
                if ":" not in parts:
                    raise ValueError(
                        "TCP endpoint must include port (format: tcp://host:port)"
                    )

                host, port_str = parts.rsplit(":", 1)

                # Validate host (prevent SSRF)
                if not host or host.strip() == "":
                    raise ValueError("TCP endpoint must include host")

                # SECURITY: Comprehensive SSRF prevention
                # Block localhost variants
                # SECURITY: This list is used for validation to BLOCK localhost access, not for binding
                blocked_hosts = [
                    "127.0.0.1",
                    "localhost",
                    "0.0.0.0",
                    "::1",
                ]  # nosec B104
                if host.lower() in blocked_hosts:
                    raise ValueError(
                        f"Endpoint host '{host}' is blocked for security (use explicit IP or hostname)"
                    )

                # Block private IP ranges (RFC 1918)
                try:
                    ip = ipaddress.ip_address(host)
                    # Check in order: loopback, link-local, multicast, reserved, then private
                    # (link-local and some others may also be private, so check specific types first)
                    if ip.is_loopback:
                        raise ValueError(
                            f"Endpoint host '{host}' is blocked for security (loopback address)"
                        )
                    if ip.is_link_local:
                        raise ValueError(
                            f"Endpoint host '{host}' is blocked for security (link-local address)"
                        )
                    if ip.is_multicast:
                        raise ValueError(
                            f"Endpoint host '{host}' is blocked for security (multicast address)"
                        )
                    if ip.is_reserved:
                        raise ValueError(
                            f"Endpoint host '{host}' is blocked for security (reserved address)"
                        )
                    if ip.is_private:
                        raise ValueError(
                            f"Endpoint host '{host}' is blocked for security (private IP range)"
                        )
                except ValueError as e:
                    # Check if this is our security exception (has "blocked for security" message)
                    if "blocked for security" in str(e):
                        # Re-raise our security exceptions
                        raise
                    # Otherwise, it's an invalid IP address format - check if it's a hostname
                    # Block cloud metadata service hostnames
                    metadata_hostnames = [
                        "169.254.169.254",  # AWS, GCP, Azure metadata
                        "metadata.google.internal",
                        "metadata.azure.com",
                        "169.254.169.254.nip.io",
                    ]
                    if host.lower() in [h.lower() for h in metadata_hostnames]:
                        raise ValueError(
                            f"Endpoint host '{host}' is blocked for security (metadata service)"
                        )

                # Validate port
                try:
                    port = int(port_str)
                    if port < 1 or port > 65535:
                        raise ValueError(
                            f"Port must be between 1 and 65535, got: {port}"
                        )
                except ValueError:
                    raise ValueError(f"Invalid port number: {port_str}")
            except (ValueError, IndexError) as e:
                # Re-raise as ValueError with context
                if isinstance(e, ValueError):
                    raise
                raise ValueError(f"Invalid TCP endpoint format: {endpoint}")

        return endpoint

    def _validate_socket_type(self, socket_type: str) -> None:
        """Validate ZeroMQ socket type."""
        valid_types = ["PUB", "PUSH", "REQ", "DEALER"]
        if socket_type not in valid_types:
            raise ValueError(
                f"Invalid socket type: {socket_type}. Must be one of: {', '.join(valid_types)}"
            )

    async def setup(self) -> None:
        """Initialize ZeroMQ context and socket."""
        if not self._validated_endpoint:
            raise ValueError("Endpoint is required and must be validated")

        try:
            self.context = zmq.asyncio.Context()

            # Map socket type string to ZMQ constant
            socket_type_map = {
                "PUB": zmq.PUB,
                "PUSH": zmq.PUSH,
                "REQ": zmq.REQ,
                "DEALER": zmq.DEALER,
            }

            self.socket = self.context.socket(socket_type_map[self.socket_type])
            self.socket.bind(self._validated_endpoint)
        except Exception as e:
            from src.utils import sanitize_error_message

            raise Exception(sanitize_error_message(e, "ZeroMQ socket creation"))

    async def teardown(self) -> None:
        """Close ZeroMQ socket and context."""
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                # SECURITY: Silently ignore socket close errors during cleanup
                # This is intentional - close failures during teardown are non-critical
                pass  # nosec B110
        if self.context:
            try:
                self.context.term()
            except Exception:
                # SECURITY: Silently ignore context termination errors during cleanup
                # This is intentional - termination failures during teardown are non-critical
                pass  # nosec B110

    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        """Publish payload to ZeroMQ socket."""
        if not self.socket:
            await self.setup()

        try:
            # Serialize payload to JSON
            if isinstance(payload, (dict, list)):
                message = json.dumps(payload)
            else:
                message = str(payload)

            # Send message
            await self.socket.send_string(message)
        except Exception as e:
            from src.utils import sanitize_error_message

            raise Exception(sanitize_error_message(e, "ZeroMQ message publishing"))
