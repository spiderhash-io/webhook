from typing import Any, Dict, Optional
import json
import re
import ipaddress
import redis
try:
    import fakeredis
except ImportError:
    fakeredis = None
from src.modules.base import BaseModule


class RedisPublishModule(BaseModule):
    """Publish webhook payloads to a Redis channel.

    The module expects the following configuration in the webhook definition:
    ```json
    {
        "module": "redis_publish",
        "redis": {
            "host": "redis",
            "port": 6379,
            "channel": "webhook_events"
        }
    }
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        # Validate channel name during initialization to fail early
        redis_cfg = self.config.get("redis", {})
        raw_channel = redis_cfg.get("channel", "webhook_events")
        self._validated_channel = self._validate_channel_name(raw_channel)
        
        # Validate Redis host and port during initialization to prevent SSRF
        raw_host = redis_cfg.get("host", "localhost")
        raw_port = redis_cfg.get("port", 6379)
        self._validated_host = self._validate_redis_host(raw_host)
        self._validated_port = self._validate_redis_port(raw_port)

    def _validate_channel_name(self, channel_name: str) -> str:
        """
        Validate and sanitize Redis channel name to prevent injection.
        
        Args:
            channel_name: The channel name from configuration
            
        Returns:
            Validated and sanitized channel name
            
        Raises:
            ValueError: If channel name is invalid or contains dangerous characters
        """
        if not channel_name or not isinstance(channel_name, str):
            raise ValueError("Channel name must be a non-empty string")
        
        # Remove whitespace
        channel_name = channel_name.strip()
        
        if not channel_name:
            raise ValueError("Channel name cannot be empty")
        
        # Maximum length to prevent DoS
        if len(channel_name) > 255:
            raise ValueError(f"Channel name too long: {len(channel_name)} characters (max: 255)")
        
        # Validate format: alphanumeric, underscore, hyphen, and dot only
        # This is more restrictive than Redis allows, but safer for security
        if not re.match(r'^[a-zA-Z0-9_\-\.]+$', channel_name):
            raise ValueError(
                f"Invalid channel name format: '{channel_name}'. "
                f"Only alphanumeric characters, underscores, hyphens, and dots are allowed."
            )
        
        # Reject dangerous patterns that could be used for injection
        dangerous_patterns = ['..', '--', ';', '/*', '*/', '(', ')', '[', ']', '{', '}', '|', '&', '$', '`']
        for pattern in dangerous_patterns:
            if pattern in channel_name:
                raise ValueError(f"Channel name contains dangerous pattern: '{pattern}'")
        
        # Reject Redis command keywords that could be used in injection
        redis_keywords = [
            'pubsub', 'publish', 'subscribe', 'psubscribe', 'unsubscribe', 'punsubscribe',
            'keys', 'get', 'set', 'del', 'exists', 'expire', 'ttl', 'flushdb', 'flushall',
            'config', 'info', 'monitor', 'debug', 'eval', 'evalsha', 'script'
        ]
        channel_name_lower = channel_name.lower()
        for keyword in redis_keywords:
            # Check if keyword appears as a standalone word or at the start
            if channel_name_lower == keyword or channel_name_lower.startswith(keyword + '.') or channel_name_lower.startswith(keyword + '_'):
                raise ValueError(f"Channel name contains forbidden Redis keyword: '{keyword}'")
        
        # Reject patterns that look like Redis command injection
        if any(char in channel_name for char in ['\r', '\n', '\0', '\t']):
            raise ValueError("Channel name contains forbidden control characters")
        
        return channel_name
    
    def _validate_redis_host(self, host: str) -> str:
        """
        Validate Redis host to prevent SSRF attacks.
        
        This function:
        - Blocks private IP ranges (RFC 1918, localhost, link-local)
        - Blocks cloud metadata endpoints
        - Validates hostname format
        - Optionally allows whitelisting specific hosts
        
        Args:
            host: Redis host to validate
            
        Returns:
            Validated host string
            
        Raises:
            ValueError: If host is invalid or poses SSRF risk
        """
        if not host or not isinstance(host, str):
            raise ValueError("Redis host must be a non-empty string")
        
        host = host.strip()
        if not host:
            raise ValueError("Redis host cannot be empty or whitespace-only")
        
        # Check for whitelist in config (optional)
        allowed_hosts = self.config.get("redis", {}).get("allowed_hosts", None)
        if allowed_hosts and isinstance(allowed_hosts, list):
            # If whitelist is configured, only allow those hosts
            allowed_hosts_lower = {h.lower().strip() for h in allowed_hosts if h}
            if host.lower() not in allowed_hosts_lower:
                raise ValueError(
                    f"Redis host '{host}' is not in the allowed hosts whitelist"
                )
            # If whitelisted, skip further validation
            return host
        
        # Block localhost and variations
        localhost_variants = {
            'localhost', '127.0.0.1', '0.0.0.0', '::1', '[::1]',
            '127.1', '127.0.1', '127.000.000.001', '0177.0.0.1',  # Octal
            '0x7f.0.0.1', '2130706433', '0x7f000001',  # Decimal/Hex
        }
        if host.lower() in localhost_variants:
            raise ValueError(
                f"Access to localhost is not allowed for security reasons"
            )
        
        # Block private IP ranges (RFC 1918)
        try:
            # Try to parse as IP address
            ip = ipaddress.ip_address(host)
            
            # Block link-local addresses FIRST (169.254.0.0/16) - these are often used for metadata
            if ip.is_link_local:
                raise ValueError(
                    f"Access to link-local address '{host}' is not allowed for security reasons"
                )
            
            # Block loopback
            if ip.is_loopback:
                raise ValueError(
                    f"Access to loopback address '{host}' is not allowed for security reasons"
                )
            
            # Block multicast addresses
            if ip.is_multicast:
                raise ValueError(
                    f"Access to multicast address '{host}' is not allowed for security reasons"
                )
            
            # Block reserved addresses
            if ip.is_reserved:
                raise ValueError(
                    f"Access to reserved IP address '{host}' is not allowed for security reasons"
                )
            
            # Block private IPs (RFC 1918)
            if ip.is_private:
                raise ValueError(
                    f"Access to private IP address '{host}' is not allowed for security reasons"
                )
            
        except ValueError as e:
            # If ValueError is raised by ipaddress, it might be our validation error
            # Re-raise it
            if "is not allowed" in str(e):
                raise
            # Otherwise, it's not an IP address (might be a hostname), continue validation
            pass
        except Exception:
            # Not an IP address, continue with hostname validation
            pass
        
        # Block common cloud metadata endpoints
        dangerous_hostnames = {
            'metadata.google.internal',
            '169.254.169.254',  # AWS, GCP, Azure metadata
            'metadata',  # Short form
        }
        if host.lower() in dangerous_hostnames:
            raise ValueError(
                f"Access to metadata service '{host}' is not allowed for security reasons"
            )
        
        # Validate hostname format (basic check)
        if not self._is_valid_ip(host):
            # Check DNS hostname format
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', host):
                raise ValueError(f"Invalid hostname format: '{host}'")
        
        return host
    
    def _is_valid_ip(self, hostname: str) -> bool:
        """Check if hostname is a valid IP address."""
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return False
    
    def _validate_redis_port(self, port: Any) -> int:
        """
        Validate Redis port to prevent SSRF attacks.
        
        This function:
        - Validates port is in valid range (1-65535)
        - Converts string ports to integers
        - Blocks common dangerous ports if needed
        
        Args:
            port: Redis port to validate
            
        Returns:
            Validated port integer
            
        Raises:
            ValueError: If port is invalid
        """
        # Convert to int if string
        if isinstance(port, str):
            port = port.strip()
            if not port:
                raise ValueError("Redis port cannot be empty")
            try:
                port = int(port)
            except ValueError:
                raise ValueError(f"Redis port must be a valid integer: '{port}'")
        
        if not isinstance(port, int):
            raise ValueError(f"Redis port must be an integer: {type(port)}")
        
        # Validate port range
        if port < 1 or port > 65535:
            raise ValueError(f"Redis port must be between 1 and 65535: {port}")
        
        # Optionally block common dangerous ports (can be configured)
        # For now, we'll allow all valid ports, but this can be restricted if needed
        
        return port

    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        # Use pre-validated host, port, and channel from __init__
        host = self._validated_host
        port = self._validated_port
        channel = self._validated_channel

        # Create a Redis client (synchronous, but fast for simple publish)
        client = redis.Redis(host=host, port=port, socket_connect_timeout=5, socket_timeout=5)
        
        # Test connection - raise exception if connection fails (for retry mechanism)
        try:
            client.ping()
        except (redis.ConnectionError, redis.TimeoutError, ConnectionRefusedError, OSError) as e:
            raise ConnectionError(f"Failed to connect to Redis at {host}:{port}: {e}")
        
        # Serialize payload and headers as JSON
        message = json.dumps({"payload": payload, "headers": dict(headers)})
        
        try:
            client.publish(channel, message)
            print(f"Published webhook payload to Redis channel '{channel}'")
        except (redis.ConnectionError, redis.TimeoutError, ConnectionRefusedError, OSError) as e:
            raise ConnectionError(f"Failed to publish to Redis channel '{channel}': {e}")
