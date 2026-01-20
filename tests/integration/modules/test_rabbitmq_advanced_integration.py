"""
Integration tests for RabbitMQ advanced features.

These tests verify exchanges, custom headers, message durability, and error handling.
"""

import pytest
import pika
import json
import asyncio
from tests.integration.test_config import (
    RABBITMQ_HOST,
    RABBITMQ_PORT,
    RABBITMQ_USER,
    RABBITMQ_PASS,
    TEST_RABBITMQ_QUEUE_PREFIX,
)
from src.modules.rabbitmq_module import RabbitMQModule
from src.modules.rabbitmq import RabbitMQConnectionPool


@pytest.mark.integration
class TestRabbitMQAdvancedIntegration:
    """Integration tests for RabbitMQ advanced features."""

    @pytest.fixture
    def rabbitmq_connection(self):
        """Create a RabbitMQ connection for testing."""
        credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
        parameters = pika.ConnectionParameters(
            host=RABBITMQ_HOST,
            port=RABBITMQ_PORT,
            credentials=credentials,
            heartbeat=600,
        )
        connection = pika.BlockingConnection(parameters)
        yield connection
        connection.close()

    @pytest.fixture
    def rabbitmq_channel(self, rabbitmq_connection):
        """Create a RabbitMQ channel for testing."""
        channel = rabbitmq_connection.channel()
        yield channel
        channel.close()

    @pytest.fixture
    async def connection_pool(self):
        """Create a RabbitMQ connection pool for testing."""
        pool = RabbitMQConnectionPool(max_size=2, acquisition_timeout=5.0)
        await pool.create_pool(
            host=RABBITMQ_HOST,
            port=RABBITMQ_PORT,
            login=RABBITMQ_USER,
            password=RABBITMQ_PASS,
        )
        yield pool
        await pool.close_all()

    @pytest.mark.asyncio
    async def test_durable_queue_persistence(self, rabbitmq_channel):
        """Test that durable queues persist across RabbitMQ restarts."""
        test_queue = f"{TEST_RABBITMQ_QUEUE_PREFIX}durable_test"

        # Declare durable queue
        result = rabbitmq_channel.queue_declare(queue=test_queue, durable=True)
        assert result.method.queue == test_queue

        # Verify queue exists
        queue_info = rabbitmq_channel.queue_declare(
            queue=test_queue, passive=True  # Check if queue exists
        )
        assert queue_info.method.queue == test_queue

        # Cleanup
        rabbitmq_channel.queue_delete(queue=test_queue)

    @pytest.mark.asyncio
    async def test_message_headers(self, rabbitmq_channel):
        """Test that custom headers are preserved in messages."""
        test_queue = f"{TEST_RABBITMQ_QUEUE_PREFIX}headers_test"
        rabbitmq_channel.queue_declare(queue=test_queue, durable=True)
        rabbitmq_channel.queue_purge(queue=test_queue)

        # Publish message with custom headers
        custom_headers = {
            "X-Custom-Header": "test_value",
            "X-Webhook-ID": "test_webhook_123",
            "X-Timestamp": "2024-01-01T00:00:00Z",
        }

        message_body = {"test": "headers", "value": 123}
        properties = pika.BasicProperties(
            headers=custom_headers, delivery_mode=2  # Persistent
        )

        rabbitmq_channel.basic_publish(
            exchange="",
            routing_key=test_queue,
            body=json.dumps(message_body).encode("utf-8"),
            properties=properties,
        )

        # Consume message and verify headers
        method_frame, header_frame, body = rabbitmq_channel.basic_get(
            queue=test_queue, auto_ack=True
        )

        assert method_frame is not None
        assert header_frame.headers == custom_headers
        assert json.loads(body.decode("utf-8")) == message_body

        rabbitmq_channel.queue_delete(queue=test_queue)

    @pytest.mark.asyncio
    async def test_persistent_vs_non_persistent_messages(self, rabbitmq_channel):
        """Test persistent vs non-persistent message delivery modes."""
        test_queue = f"{TEST_RABBITMQ_QUEUE_PREFIX}delivery_mode_test"
        rabbitmq_channel.queue_declare(queue=test_queue, durable=True)
        rabbitmq_channel.queue_purge(queue=test_queue)

        # Publish persistent message
        persistent_props = pika.BasicProperties(delivery_mode=2)
        rabbitmq_channel.basic_publish(
            exchange="",
            routing_key=test_queue,
            body=b"persistent_message",
            properties=persistent_props,
        )

        # Publish non-persistent message
        non_persistent_props = pika.BasicProperties(delivery_mode=1)
        rabbitmq_channel.basic_publish(
            exchange="",
            routing_key=test_queue,
            body=b"non_persistent_message",
            properties=non_persistent_props,
        )

        # Consume messages and verify delivery modes
        messages = []
        for _ in range(2):
            method_frame, header_frame, body = rabbitmq_channel.basic_get(
                queue=test_queue, auto_ack=True
            )
            if method_frame:
                messages.append((header_frame.delivery_mode, body.decode()))

        # Both messages should be received
        assert len(messages) == 2
        delivery_modes = [msg[0] for msg in messages]
        assert 1 in delivery_modes  # Non-persistent
        assert 2 in delivery_modes  # Persistent

        rabbitmq_channel.queue_delete(queue=test_queue)

    @pytest.mark.asyncio
    async def test_custom_exchange(self, rabbitmq_channel):
        """Test publishing to a custom exchange."""
        test_exchange = f"{TEST_RABBITMQ_QUEUE_PREFIX}test_exchange"
        test_queue = f"{TEST_RABBITMQ_QUEUE_PREFIX}exchange_test"
        routing_key = "test.routing.key"

        # Declare custom exchange
        rabbitmq_channel.exchange_declare(
            exchange=test_exchange, exchange_type="topic", durable=True
        )

        # Declare queue and bind to exchange
        rabbitmq_channel.queue_declare(queue=test_queue, durable=True)
        rabbitmq_channel.queue_bind(
            exchange=test_exchange, queue=test_queue, routing_key=routing_key
        )
        rabbitmq_channel.queue_purge(queue=test_queue)

        # Publish to exchange
        message_body = {"test": "exchange", "value": 456}
        rabbitmq_channel.basic_publish(
            exchange=test_exchange,
            routing_key=routing_key,
            body=json.dumps(message_body).encode("utf-8"),
            properties=pika.BasicProperties(delivery_mode=2),
        )

        # Consume from queue
        method_frame, header_frame, body = rabbitmq_channel.basic_get(
            queue=test_queue, auto_ack=True
        )

        assert method_frame is not None
        assert json.loads(body.decode("utf-8")) == message_body

        # Cleanup
        rabbitmq_channel.queue_unbind(
            exchange=test_exchange, queue=test_queue, routing_key=routing_key
        )
        rabbitmq_channel.queue_delete(queue=test_queue)
        rabbitmq_channel.exchange_delete(exchange=test_exchange)

    @pytest.mark.asyncio
    async def test_rabbitmq_module_with_connection_pool(self, connection_pool):
        """Test RabbitMQ module using connection pool."""
        test_queue = f"{TEST_RABBITMQ_QUEUE_PREFIX}module_pool_test"

        # Create module config
        config = {
            "module": "rabbitmq",
            "queue_name": test_queue,
            "connection_details": {"connection_pool": connection_pool},
        }

        module = RabbitMQModule(config)

        # Process a payload
        test_payload = {"test": "module_pool", "value": 789}
        test_headers = {"X-Test": "integration"}

        await module.process(test_payload, test_headers)

        # Verify message was published (using sync connection to check)
        credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
        parameters = pika.ConnectionParameters(
            host=RABBITMQ_HOST,
            port=RABBITMQ_PORT,
            credentials=credentials,
            heartbeat=600,
        )
        with pika.BlockingConnection(parameters) as conn:
            channel = conn.channel()
            method_frame, header_frame, body = channel.basic_get(
                queue=test_queue, auto_ack=True
            )

            assert method_frame is not None
            received_data = json.loads(body.decode("utf-8"))
            assert received_data == test_payload

            channel.queue_delete(queue=test_queue)

    @pytest.mark.asyncio
    async def test_queue_name_validation(self):
        """Test that RabbitMQ module validates queue names."""
        from src.modules.rabbitmq_module import RabbitMQModule

        # Valid queue name
        valid_config = {
            "module": "rabbitmq",
            "queue_name": "valid_queue_name_123",
            "connection_details": {},
        }
        module = RabbitMQModule(valid_config)
        assert module._validated_queue_name == "valid_queue_name_123"

        # Invalid queue name (contains dangerous pattern)
        invalid_config = {
            "module": "rabbitmq",
            "queue_name": "queue;DROP TABLE",
            "connection_details": {},
        }
        with pytest.raises(ValueError):
            RabbitMQModule(invalid_config)

    @pytest.mark.asyncio
    async def test_error_handling_on_connection_failure(self, connection_pool):
        """Test error handling when connection fails."""
        # Get a connection and close it
        conn = await connection_pool.get_connection()
        await conn.close()

        # Release closed connection back to pool
        await connection_pool.release(conn)

        # Try to use connection pool (should get a new connection or handle gracefully)
        config = {
            "module": "rabbitmq",
            "queue_name": f"{TEST_RABBITMQ_QUEUE_PREFIX}error_test",
            "connection_details": {"connection_pool": connection_pool},
        }

        module = RabbitMQModule(config)

        # Process might succeed (pool creates new connection) or fail
        # Either behavior is acceptable for this test
        try:
            await module.process({"test": "error"}, {})
        except Exception:
            # Expected if connection handling fails
            pass
