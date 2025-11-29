"""
Integration tests for Kafka module with Redpanda.

These tests verify Kafka topic validation, message publishing, and connection handling.
"""

import pytest
import asyncio
from aiokafka import AIOKafkaConsumer
from aiokafka.errors import KafkaError
from tests.integration.test_config import KAFKA_BOOTSTRAP_SERVERS, KAFKA_HOST, KAFKA_PORT, TEST_KAFKA_TOPIC_PREFIX
from src.modules.kafka import KafkaModule


@pytest.mark.integration
class TestKafkaIntegration:
    """Integration tests for Kafka module."""
    
    @pytest.fixture
    async def kafka_consumer(self):
        """Create a Kafka consumer for testing."""
        consumer = AIOKafkaConsumer(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            auto_offset_reset='earliest',
            enable_auto_commit=False
        )
        await consumer.start()
        yield consumer
        await consumer.stop()
    
    @pytest.mark.asyncio
    async def test_kafka_connection(self):
        """Test that we can connect to Kafka/Redpanda."""
        # Test connection by creating a producer
        from aiokafka import AIOKafkaProducer
        import json
        
        producer = AIOKafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
        try:
            await producer.start()
            # If we get here without exception, connection succeeded
            # Verify producer is initialized
            assert producer is not None
        finally:
            await producer.stop()
    
    @pytest.mark.asyncio
    async def test_kafka_topic_validation(self):
        """Test that Kafka module validates topic names."""
        from src.modules.kafka import KafkaModule
        
        # Valid topic name
        valid_config = {
            "module": "kafka",
            "topic": "valid_topic_name_123",
            "connection_details": {
                "bootstrap_servers": KAFKA_BOOTSTRAP_SERVERS
            }
        }
        module = KafkaModule(valid_config)
        assert module._validated_topic == "valid_topic_name_123"
        
        # Invalid topic name (contains dangerous pattern)
        invalid_config = {
            "module": "kafka",
            "topic": "topic;DELETE",
            "connection_details": {
                "bootstrap_servers": KAFKA_BOOTSTRAP_SERVERS
            }
        }
        with pytest.raises(ValueError, match="Invalid topic name format|dangerous|forbidden"):
            KafkaModule(invalid_config)
    
    @pytest.mark.asyncio
    async def test_kafka_message_publishing(self, kafka_consumer):
        """Test that we can publish messages to Kafka topics."""
        test_topic = f"{TEST_KAFKA_TOPIC_PREFIX}message_test"
        
        # Create module
        config = {
            "module": "kafka",
            "topic": test_topic,
            "connection_details": {
                "bootstrap_servers": KAFKA_BOOTSTRAP_SERVERS
            }
        }
        
        module = KafkaModule(config)
        
        # Test payload
        test_payload = {"event": "kafka_test", "data": {"value": 123}}
        test_headers = {"X-Test": "integration"}
        
        # Publish message
        await module.process(test_payload, test_headers)
        
        # Consume message
        kafka_consumer.subscribe([test_topic])
        
        # Wait for message (with timeout)
        try:
            msg = await asyncio.wait_for(
                kafka_consumer.getone(),
                timeout=5.0
            )
            
            # Verify message
            import json
            received_data = json.loads(msg.value.decode('utf-8'))
            assert received_data == test_payload
            
        except asyncio.TimeoutError:
            pytest.fail("Message not received within timeout")
        finally:
            if module.producer:
                await module.teardown()
    
    @pytest.mark.asyncio
    async def test_kafka_message_with_key(self, kafka_consumer):
        """Test publishing messages with a key."""
        test_topic = f"{TEST_KAFKA_TOPIC_PREFIX}key_test"
        
        config = {
            "module": "kafka",
            "topic": test_topic,
            "module-config": {
                "key": "test_key_123"
            },
            "connection_details": {
                "bootstrap_servers": KAFKA_BOOTSTRAP_SERVERS
            }
        }
        
        module = KafkaModule(config)
        
        test_payload = {"event": "key_test", "data": {"value": 456}}
        
        await module.process(test_payload, {})
        
        # Consume message
        kafka_consumer.subscribe([test_topic])
        
        try:
            msg = await asyncio.wait_for(
                kafka_consumer.getone(),
                timeout=5.0
            )
            
            # Verify key
            assert msg.key.decode('utf-8') == "test_key_123"
            
            import json
            received_data = json.loads(msg.value.decode('utf-8'))
            assert received_data == test_payload
            
        except asyncio.TimeoutError:
            pytest.fail("Message not received within timeout")
        finally:
            if module.producer:
                await module.teardown()
    
    @pytest.mark.asyncio
    async def test_kafka_message_with_headers(self, kafka_consumer):
        """Test publishing messages with headers."""
        test_topic = f"{TEST_KAFKA_TOPIC_PREFIX}headers_test"
        
        config = {
            "module": "kafka",
            "topic": test_topic,
            "module-config": {
                "forward_headers": True
            },
            "connection_details": {
                "bootstrap_servers": KAFKA_BOOTSTRAP_SERVERS
            }
        }
        
        module = KafkaModule(config)
        
        test_payload = {"event": "headers_test", "data": {"value": 789}}
        test_headers = {
            "Authorization": "Bearer token123",
            "X-Custom": "custom_value"
        }
        
        await module.process(test_payload, test_headers)
        
        # Consume message
        kafka_consumer.subscribe([test_topic])
        
        try:
            msg = await asyncio.wait_for(
                kafka_consumer.getone(),
                timeout=5.0
            )
            
            # Verify headers
            assert msg.headers is not None
            header_dict = {k: v.decode('utf-8') for k, v in msg.headers}
            assert "Authorization" in header_dict
            assert header_dict["Authorization"] == "Bearer token123"
            assert header_dict["X-Custom"] == "custom_value"
            
        except asyncio.TimeoutError:
            pytest.fail("Message not received within timeout")
        finally:
            if module.producer:
                await module.teardown()
    
    @pytest.mark.asyncio
    async def test_kafka_connection_error_handling(self):
        """Test handling of connection failures."""
        # Try to connect to invalid broker
        config = {
            "module": "kafka",
            "topic": "test_topic",
            "connection_details": {
                "bootstrap_servers": "invalid_host:9092"
            }
        }
        
        module = KafkaModule(config)
        
        # Process should raise connection error
        with pytest.raises(Exception, match="Kafka|connection|operation"):
            await module.process({"test": "data"}, {})
    
    @pytest.mark.asyncio
    async def test_kafka_topic_name_length_validation(self):
        """Test that topic name length is validated."""
        from src.modules.kafka import KafkaModule
        
        # Topic name too long
        long_topic = "a" * 250  # 250 characters (exceeds 249 limit)
        
        config = {
            "module": "kafka",
            "topic": long_topic,
            "connection_details": {
                "bootstrap_servers": KAFKA_BOOTSTRAP_SERVERS
            }
        }
        
        with pytest.raises(ValueError, match="too long"):
            KafkaModule(config)
    
    @pytest.mark.asyncio
    async def test_kafka_topic_name_short_validation(self):
        """Test that topic name minimum length is validated."""
        from src.modules.kafka import KafkaModule
        
        # Topic name too short
        short_topic = "a"  # 1 character (minimum is 2)
        
        config = {
            "module": "kafka",
            "topic": short_topic,
            "connection_details": {
                "bootstrap_servers": KAFKA_BOOTSTRAP_SERVERS
            }
        }
        
        with pytest.raises(ValueError, match="too short"):
            KafkaModule(config)
    
    @pytest.mark.asyncio
    async def test_kafka_multiple_messages(self, kafka_consumer):
        """Test publishing multiple messages to the same topic."""
        test_topic = f"{TEST_KAFKA_TOPIC_PREFIX}multiple_test"
        
        config = {
            "module": "kafka",
            "topic": test_topic,
            "connection_details": {
                "bootstrap_servers": KAFKA_BOOTSTRAP_SERVERS
            }
        }
        
        module = KafkaModule(config)
        
        # Publish multiple messages
        messages = []
        for i in range(5):
            payload = {"event": "multiple_test", "index": i, "data": {"value": i * 10}}
            await module.process(payload, {})
            messages.append(payload)
        
        # Consume messages
        kafka_consumer.subscribe([test_topic])
        
        received_messages = []
        try:
            for _ in range(5):
                msg = await asyncio.wait_for(
                    kafka_consumer.getone(),
                    timeout=5.0
                )
                import json
                received_data = json.loads(msg.value.decode('utf-8'))
                received_messages.append(received_data)
        except asyncio.TimeoutError:
            pass
        
        # Verify we received all messages
        assert len(received_messages) == 5
        
        # Verify message content
        for msg in received_messages:
            assert "event" in msg
            assert msg["event"] == "multiple_test"
            assert "index" in msg
        
        if module.producer:
            await module.teardown()
    
    @pytest.mark.asyncio
    async def test_kafka_producer_reuse(self, kafka_consumer):
        """Test that producer is reused across multiple calls."""
        test_topic = f"{TEST_KAFKA_TOPIC_PREFIX}reuse_test"
        
        config = {
            "module": "kafka",
            "topic": test_topic,
            "connection_details": {
                "bootstrap_servers": KAFKA_BOOTSTRAP_SERVERS
            }
        }
        
        module = KafkaModule(config)
        
        # First call should create producer
        await module.process({"test": "first"}, {})
        producer1 = module.producer
        
        # Second call should reuse producer
        await module.process({"test": "second"}, {})
        producer2 = module.producer
        
        # Should be the same producer instance
        assert producer1 is producer2
        
        if module.producer:
            await module.teardown()

