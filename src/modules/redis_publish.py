from typing import Any, Dict
import json
import re
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

    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        # Resolve Redis connection details from the connection config
        redis_cfg = self.config.get("redis", {})
        host = redis_cfg.get("host", "localhost")
        port = redis_cfg.get("port", 6379)
        # Use pre-validated channel name from __init__
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
