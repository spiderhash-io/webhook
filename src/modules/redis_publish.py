from typing import Any, Dict
import json
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
    ```
    """

    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        # Resolve Redis connection details from the connection config
        redis_cfg = self.config.get("redis", {})
        host = redis_cfg.get("host", "localhost")
        port = redis_cfg.get("port", 6379)
        channel = redis_cfg.get("channel", "webhook_events")

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
