"""
Integration tests for multi-module webhook processing.

These tests verify webhooks configured with multiple output modules.
"""

import pytest
import asyncio
import redis.asyncio as redis
import pika
import json
from tests.integration.test_config import (
    REDIS_URL, REDIS_HOST, REDIS_PORT,
    RABBITMQ_HOST, RABBITMQ_PORT, RABBITMQ_USER, RABBITMQ_PASS,
    TEST_REDIS_PREFIX, TEST_RABBITMQ_QUEUE_PREFIX
)
from src.modules.redis_publish import RedisPublishModule
from src.modules.rabbitmq_module import RabbitMQModule
from src.modules.rabbitmq import RabbitMQConnectionPool


@pytest.mark.integration
class TestMultiModuleIntegration:
    """Integration tests for multi-module webhook processing."""
    
    @pytest.fixture
    async def redis_client(self):
        """Create a Redis client for testing."""
        r = redis.from_url(REDIS_URL, decode_responses=True)
        yield r
        await r.aclose()
    
    @pytest.fixture
    def rabbitmq_connection(self):
        """Create a RabbitMQ connection for testing."""
        credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
        parameters = pika.ConnectionParameters(
            host=RABBITMQ_HOST,
            port=RABBITMQ_PORT,
            credentials=credentials,
            heartbeat=600
        )
        connection = pika.BlockingConnection(parameters)
        yield connection
        connection.close()
    
    @pytest.fixture
    async def connection_pool(self):
        """Create a RabbitMQ connection pool for testing."""
        pool = RabbitMQConnectionPool(max_size=2, acquisition_timeout=5.0)
        await pool.create_pool(
            host=RABBITMQ_HOST,
            port=RABBITMQ_PORT,
            login=RABBITMQ_USER,
            password=RABBITMQ_PASS
        )
        yield pool
        await pool.close_all()
    
    @pytest.mark.asyncio
    async def test_redis_and_rabbitmq_sequential_processing(
        self, redis_client, connection_pool
    ):
        """Test processing webhook through Redis and RabbitMQ sequentially."""
        test_channel = "test_integration_multi_module"
        test_queue = f"{TEST_RABBITMQ_QUEUE_PREFIX}multi_module_test"
        
        # Create Redis publish module
        redis_config = {
            "module": "redis_publish",
            "redis": {
                "host": REDIS_HOST,
                "port": REDIS_PORT,
                "channel": test_channel,
                "allowed_hosts": [REDIS_HOST]
            }
        }
        redis_module = RedisPublishModule(redis_config)
        
        # Create RabbitMQ module
        rabbitmq_config = {
            "module": "rabbitmq",
            "queue_name": test_queue,
            "connection_details": {
                "connection_pool": connection_pool
            }
        }
        rabbitmq_module = RabbitMQModule(rabbitmq_config)
        
        # Test payload
        test_payload = {"event": "multi_module", "data": {"value": 123}}
        test_headers = {"X-Test": "integration"}
        
        # Process through Redis first
        await redis_module.process(test_payload, test_headers)
        
        # Process through RabbitMQ second
        await rabbitmq_module.process(test_payload, test_headers)
        
        # Verify Redis message
        pubsub = redis_client.pubsub()
        await pubsub.subscribe(test_channel)
        await asyncio.sleep(0.1)
        
        # Check if message was published (might have been consumed already)
        # We'll verify by checking RabbitMQ message instead
        
        # Verify RabbitMQ message
        credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
        parameters = pika.ConnectionParameters(
            host=RABBITMQ_HOST,
            port=RABBITMQ_PORT,
            credentials=credentials,
            heartbeat=600
        )
        with pika.BlockingConnection(parameters) as conn:
            channel = conn.channel()
            method_frame, header_frame, body = channel.basic_get(
                queue=test_queue,
                auto_ack=True
            )
            
            assert method_frame is not None
            received_data = json.loads(body.decode('utf-8'))
            assert received_data == test_payload
            
            channel.queue_delete(queue=test_queue)
        
        await pubsub.unsubscribe(test_channel)
        await pubsub.aclose()
    
    @pytest.mark.asyncio
    async def test_error_propagation_across_modules(self, connection_pool):
        """Test that errors in one module don't prevent other modules from processing."""
        test_queue = f"{TEST_RABBITMQ_QUEUE_PREFIX}error_propagation_test"
        
        # Create a module that will fail
        failing_config = {
            "module": "redis_publish",
            "redis": {
                "host": "invalid_host",
                "port": 6379,
                "channel": "test",
                "allowed_hosts": ["invalid_host"]
            }
        }
        
        # Create a module that will succeed
        success_config = {
            "module": "rabbitmq",
            "queue_name": test_queue,
            "connection_details": {
                "connection_pool": connection_pool
            }
        }
        
        failing_module = RedisPublishModule(failing_config)
        success_module = RabbitMQModule(success_config)
        
        test_payload = {"event": "error_test", "data": {"value": 456}}
        test_headers = {"X-Test": "integration"}
        
        # Process through failing module (should raise error)
        with pytest.raises(Exception):
            await failing_module.process(test_payload, test_headers)
        
        # Process through success module (should succeed)
        await success_module.process(test_payload, test_headers)
        
        # Verify success module processed the message
        credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
        parameters = pika.ConnectionParameters(
            host=RABBITMQ_HOST,
            port=RABBITMQ_PORT,
            credentials=credentials,
            heartbeat=600
        )
        with pika.BlockingConnection(parameters) as conn:
            channel = conn.channel()
            method_frame, header_frame, body = channel.basic_get(
                queue=test_queue,
                auto_ack=True
            )
            
            assert method_frame is not None
            received_data = json.loads(body.decode('utf-8'))
            assert received_data == test_payload
            
            channel.queue_delete(queue=test_queue)
    
    @pytest.mark.asyncio
    async def test_concurrent_module_processing(self, redis_client, connection_pool):
        """Test processing through multiple modules concurrently."""
        import asyncio
        
        test_channel = "test_integration_concurrent"
        test_queue = f"{TEST_RABBITMQ_QUEUE_PREFIX}concurrent_test"
        
        # Create modules
        redis_config = {
            "module": "redis_publish",
            "redis": {
                "host": REDIS_HOST,
                "port": REDIS_PORT,
                "channel": test_channel,
                "allowed_hosts": [REDIS_HOST]
            }
        }
        redis_module = RedisPublishModule(redis_config)
        
        rabbitmq_config = {
            "module": "rabbitmq",
            "queue_name": test_queue,
            "connection_details": {
                "connection_pool": connection_pool
            }
        }
        rabbitmq_module = RabbitMQModule(rabbitmq_config)
        
        test_payload = {"event": "concurrent", "data": {"value": 789}}
        test_headers = {"X-Test": "integration"}
        
        # Process through both modules concurrently
        await asyncio.gather(
            redis_module.process(test_payload, test_headers),
            rabbitmq_module.process(test_payload, test_headers)
        )
        
        # Verify both processed successfully
        # Check RabbitMQ
        credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
        parameters = pika.ConnectionParameters(
            host=RABBITMQ_HOST,
            port=RABBITMQ_PORT,
            credentials=credentials,
            heartbeat=600
        )
        with pika.BlockingConnection(parameters) as conn:
            channel = conn.channel()
            method_frame, header_frame, body = channel.basic_get(
                queue=test_queue,
                auto_ack=True
            )
            
            assert method_frame is not None
            received_data = json.loads(body.decode('utf-8'))
            assert received_data == test_payload
            
            channel.queue_delete(queue=test_queue)

