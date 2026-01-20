import aio_pika
import json
import re
from typing import Any, Dict
from src.modules.base import BaseModule


class RabbitMQModule(BaseModule):
    """Module for publishing webhook payloads to RabbitMQ."""

    def __init__(self, config: Dict[str, Any], pool_registry=None):
        super().__init__(config, pool_registry)
        # Validate queue name during initialization to fail early
        # Queue name should be in module-config, not top-level config
        raw_queue_name = self.module_config.get("queue_name")
        # Fallback to top-level for backward compatibility (deprecated)
        if raw_queue_name is None:
            raw_queue_name = self.config.get("queue_name")
        if raw_queue_name is not None:
            # Validate even if empty string (will raise ValueError)
            self._validated_queue_name = self._validate_queue_name(raw_queue_name)
        else:
            # None is allowed but will fail in process() method
            self._validated_queue_name = None

    def _validate_queue_name(self, queue_name: str) -> str:
        """
        Validate and sanitize RabbitMQ queue name to prevent injection.

        Args:
            queue_name: The queue name from configuration

        Returns:
            Validated and sanitized queue name

        Raises:
            ValueError: If queue name is invalid or contains dangerous characters
        """
        if not queue_name or not isinstance(queue_name, str):
            raise ValueError("Queue name must be a non-empty string")

        # Remove whitespace
        queue_name = queue_name.strip()

        if not queue_name:
            raise ValueError("Queue name cannot be empty")

        # Maximum length to prevent DoS (RabbitMQ limit is typically 255)
        if len(queue_name) > 255:
            raise ValueError(
                f"Queue name too long: {len(queue_name)} characters (max: 255)"
            )

        # Validate format: alphanumeric, underscore, hyphen, dot, and colon only
        # RabbitMQ allows more characters, but we restrict for security
        if not re.match(r"^[a-zA-Z0-9_\-\.:]+$", queue_name):
            raise ValueError(
                f"Invalid queue name format: '{queue_name}'. "
                f"Only alphanumeric characters, underscores, hyphens, dots, and colons are allowed."
            )

        # Reject dangerous patterns that could be used for injection
        dangerous_patterns = [
            "..",
            "--",
            ";",
            "/*",
            "*/",
            "(",
            ")",
            "[",
            "]",
            "{",
            "}",
            "|",
            "&",
            "$",
            "`",
            "\\",
            "/",
        ]
        for pattern in dangerous_patterns:
            if pattern in queue_name:
                raise ValueError(f"Queue name contains dangerous pattern: '{pattern}'")

        # Reject RabbitMQ command keywords that could be used in injection
        rabbitmq_keywords = [
            "amq.",
            "amqdefault",
            "declare",
            "bind",
            "unbind",
            "delete",
            "purge",
            "get",
            "ack",
            "nack",
            "reject",
            "consume",
            "cancel",
            "publish",
        ]
        queue_name_lower = queue_name.lower()
        for keyword in rabbitmq_keywords:
            # Check if keyword appears as a standalone word or at the start
            if (
                queue_name_lower == keyword
                or queue_name_lower.startswith(keyword + ".")
                or queue_name_lower.startswith(keyword + "_")
                or queue_name_lower.startswith(keyword + "-")
            ):
                raise ValueError(
                    f"Queue name contains forbidden RabbitMQ keyword: '{keyword}'"
                )

        # Reject patterns that look like command injection
        if any(char in queue_name for char in ["\r", "\n", "\0", "\t"]):
            raise ValueError("Queue name contains forbidden control characters")

        # Reject queue names starting with 'amq.' (reserved for RabbitMQ system queues)
        if queue_name_lower.startswith("amq."):
            raise ValueError(
                "Queue name cannot start with 'amq.' (reserved for system queues)"
            )

        return queue_name

    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        """Publish payload to RabbitMQ queue."""
        headers_dict = dict(headers.items())

        queue_name = self._validated_queue_name

        if not queue_name:
            raise ValueError("Queue name is required and must be validated")

        # Get connection pool from pool_registry or fallback to connection_details
        connection_pool = None
        connection_name = self.config.get("connection")
        if self.pool_registry and connection_name:
            connection_config = self.connection_details
            if connection_config:
                from src.connection_pool_registry import create_rabbitmq_pool

                connection_pool = await self.pool_registry.get_pool(
                    connection_name, connection_config, create_rabbitmq_pool
                )

        # Fallback to connection_details if pool_registry not available
        if not connection_pool:
            connection_pool = self.connection_details.get("connection_pool")

        if not connection_pool:
            raise Exception("Connection pool is not defined")

        connection = await connection_pool.get_connection()

        if connection is None:
            raise Exception("Could not acquire a connection from the pool")

        try:
            # Create a new channel
            channel = await connection.channel()

            # Declare a queue (ensure it exists)
            queue = await channel.declare_queue(queue_name, durable=True)

            # Serialize the payload to JSON
            json_body = json.dumps(payload).encode()

            # Create the message
            message = aio_pika.Message(
                body=json_body, headers=headers_dict, delivery_mode=2
            )

            # Send the message
            await channel.default_exchange.publish(message, routing_key=queue_name)

            print("Message published to: " + str(queue_name))
        except Exception as e:
            # Log detailed error server-side
            print(f"Failed to publish message to RabbitMQ: {e}")
            # Raise generic error to client (don't expose RabbitMQ details)
            from src.utils import sanitize_error_message

            raise Exception(sanitize_error_message(e, "RabbitMQ operation"))
        finally:
            # Always release the connection back to the pool
            await connection_pool.release(connection)
