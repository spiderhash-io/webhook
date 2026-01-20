"""
Amazon SQS module for publishing webhook payloads to AWS SQS queues.
"""

import json
import re
import asyncio
from typing import Any, Dict, Optional
from src.modules.base import BaseModule
from src.utils import sanitize_error_message

try:
    import boto3
    from botocore.exceptions import ClientError

    AWS_SQS_AVAILABLE = True
except ImportError:
    AWS_SQS_AVAILABLE = False


class AWSSQSModule(BaseModule):
    """Module for publishing webhook payloads to Amazon SQS queues."""

    def __init__(self, config: Dict[str, Any], **kwargs):
        super().__init__(config, **kwargs)
        if not AWS_SQS_AVAILABLE:
            raise ImportError(
                "boto3 library is required for AWS SQS module. Install with: pip install boto3"
            )

        self.sqs_client = None

        # Validate queue URL or name during initialization
        raw_queue = self.module_config.get("queue_url") or self.module_config.get(
            "queue_name"
        )
        if raw_queue is not None:
            # SECURITY: Validate type before processing
            if not isinstance(raw_queue, str):
                raise ValueError("Queue URL or name must be a string")
            self._validated_queue = self._validate_queue(raw_queue)
            self.is_queue_url = "queue_url" in self.module_config
        else:
            self._validated_queue = None
            self.is_queue_url = False

    def _validate_queue(self, queue: str) -> str:
        """
        Validate SQS queue URL or name to prevent injection.

        Args:
            queue: The queue URL or queue name

        Returns:
            Validated queue identifier

        Raises:
            ValueError: If queue is invalid or contains dangerous characters
        """
        if not queue or not isinstance(queue, str):
            raise ValueError("Queue URL or name must be a non-empty string")

        queue = queue.strip()

        if not queue:
            raise ValueError("Queue URL or name cannot be empty")

        # Maximum length to prevent DoS (SQS queue URLs can be up to 80 chars, names up to 80)
        MAX_QUEUE_LENGTH = 80
        if len(queue) > MAX_QUEUE_LENGTH:
            raise ValueError(
                f"Queue identifier too long: {len(queue)} characters (max: {MAX_QUEUE_LENGTH})"
            )

        # If it's a queue URL, validate format
        if queue.startswith("https://") or queue.startswith("http://"):
            # Validate SQS URL format
            if "sqs." not in queue.lower() and "amazonaws.com" not in queue.lower():
                raise ValueError("Invalid SQS queue URL format")

            # SECURITY: Block SSRF attempts
            # SQS URLs should only point to AWS endpoints
            if (
                not queue.lower().startswith("https://sqs.")
                or "amazonaws.com" not in queue.lower()
            ):
                raise ValueError("Queue URL must be a valid AWS SQS URL")
        else:
            # It's a queue name - validate format
            # SQS queue names: alphanumeric, hyphens, underscores (1-80 chars)
            if not re.match(r"^[a-zA-Z0-9_-]+$", queue):
                raise ValueError(
                    f"Invalid queue name format: '{queue}'. "
                    f"Only alphanumeric characters, underscores, and hyphens are allowed."
                )

            # Minimum length
            if len(queue) < 1:
                raise ValueError("Queue name too short")

            # Reject dangerous patterns
            dangerous_patterns = [
                "..",
                "--",
                "__",
                ";",
                "|",
                "&",
                "$",
                "`",
                "\\",
                "/",
                "(",
                ")",
                "[",
                "]",
                "{",
                "}",
            ]
            for pattern in dangerous_patterns:
                if pattern in queue:
                    raise ValueError(
                        f"Queue name contains dangerous pattern: '{pattern}'"
                    )

        # Reject control characters
        if any(char in queue for char in ["\r", "\n", "\0", "\t"]):
            raise ValueError("Queue identifier contains forbidden control characters")

        return queue

    async def setup(self) -> None:
        """Initialize AWS SQS client."""
        if not self._validated_queue:
            raise ValueError("Queue URL or name is required and must be validated")

        try:
            # Get AWS credentials from connection details
            aws_access_key_id = self.connection_details.get("aws_access_key_id")
            aws_secret_access_key = self.connection_details.get("aws_secret_access_key")
            region_name = self.connection_details.get("region_name", "us-east-1")

            # SECURITY: Validate region name
            if not region_name or not isinstance(region_name, str):
                raise ValueError("Region name must be a non-empty string")

            # Validate region format (AWS region names: us-east-1, eu-west-1, etc.)
            if not re.match(r"^[a-z0-9-]+$", region_name.lower()):
                raise ValueError(f"Invalid AWS region format: {region_name}")

            # Create SQS client
            if aws_access_key_id and aws_secret_access_key:
                self.sqs_client = boto3.client(
                    "sqs",
                    aws_access_key_id=aws_access_key_id,
                    aws_secret_access_key=aws_secret_access_key,
                    region_name=region_name,
                )
            else:
                # Use default credentials (from environment, IAM role, etc.)
                self.sqs_client = boto3.client("sqs", region_name=region_name)
        except Exception as e:
            raise Exception(sanitize_error_message(e, "AWS SQS client creation"))

    async def teardown(self) -> None:
        """Close AWS SQS client."""
        # boto3 clients don't need explicit cleanup
        self.sqs_client = None

    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        """Publish payload to AWS SQS queue."""
        if not self.sqs_client:
            await self.setup()

        try:
            # Serialize payload to JSON
            if isinstance(payload, (dict, list)):
                message_body = json.dumps(payload)
            else:
                message_body = str(payload)

            # Determine queue identifier
            if self.is_queue_url:
                queue_url = self._validated_queue
            else:
                # Get queue URL from name (boto3 is synchronous, wrap in executor)
                loop = asyncio.get_event_loop()

                def get_queue_url():
                    try:
                        response = self.sqs_client.get_queue_url(
                            QueueName=self._validated_queue
                        )
                        return response["QueueUrl"]
                    except ClientError as e:
                        error_code = e.response.get("Error", {}).get("Code", "")
                        if error_code == "AWS.SimpleQueueService.NonExistentQueue":
                            # Queue doesn't exist - raise to handle in outer try-except
                            raise
                        raise Exception(
                            sanitize_error_message(e, "SQS queue URL retrieval")
                        )

                try:
                    queue_url = await loop.run_in_executor(None, get_queue_url)
                except ClientError as e:
                    # Check if it's a NonExistentQueue error
                    error_code = e.response.get("Error", {}).get("Code", "")
                    if error_code == "AWS.SimpleQueueService.NonExistentQueue":
                        # Queue doesn't exist - try to create it (for development/testing with LocalStack)
                        try:
                            print(
                                f"Queue '{self._validated_queue}' not found, attempting to create it..."
                            )

                            def create_queue():
                                # Create queue with default attributes
                                response = self.sqs_client.create_queue(
                                    QueueName=self._validated_queue
                                )
                                return response["QueueUrl"]

                            queue_url = await loop.run_in_executor(None, create_queue)
                            print(f"Created queue '{self._validated_queue}'")
                        except Exception as create_error:
                            # If creation fails, raise original error
                            sanitized_error = sanitize_error_message(
                                create_error, "SQS queue creation"
                            )
                            print(f"ERROR [SQS queue creation]: {sanitized_error}")
                            raise Exception(
                                f"Queue '{self._validated_queue}' not found and could not be created: {sanitized_error}"
                            )
                    else:
                        # Re-raise other ClientError
                        raise Exception(
                            sanitize_error_message(e, "SQS queue URL retrieval")
                        )
                except Exception as e:
                    # Re-raise other errors
                    raise Exception(
                        sanitize_error_message(e, "SQS queue URL retrieval")
                    )

            # Send message (boto3 is synchronous, wrap in executor)
            message_attributes = {}
            # Add headers as message attributes (SQS supports string attributes)
            for key, value in headers.items():
                if (
                    isinstance(value, str) and len(value) <= 256
                ):  # SQS attribute value limit
                    message_attributes[key] = {
                        "StringValue": value,
                        "DataType": "String",
                    }

            loop = asyncio.get_event_loop()

            def send_message():
                self.sqs_client.send_message(
                    QueueUrl=queue_url,
                    MessageBody=message_body,
                    MessageAttributes=(
                        message_attributes if message_attributes else None
                    ),
                )

            await loop.run_in_executor(None, send_message)
        except Exception as e:
            raise Exception(sanitize_error_message(e, "AWS SQS message publishing"))
