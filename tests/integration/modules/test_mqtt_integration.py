"""
Integration tests for MQTT module with Mosquitto broker.

These tests verify MQTT topic validation, message publishing, QoS levels,
retained messages, and connection handling with a real MQTT broker.
"""
import pytest
import asyncio
import json
from aiomqtt import Client as MQTTClient
from tests.integration.test_config import (
    MQTT_HOST, MQTT_PORT, MQTT_TLS_PORT, TEST_MQTT_TOPIC_PREFIX
)
from src.modules.mqtt import MQTTModule


@pytest.mark.integration
class TestMQTTIntegration:
    """Integration tests for MQTT module."""
    
    @pytest.fixture
    async def mqtt_consumer(self):
        """Create an MQTT consumer for testing."""
        client = MQTTClient(
            hostname=MQTT_HOST,
            port=MQTT_PORT
        )
        await client.__aenter__()
        yield client
        await client.__aexit__(None, None, None)
    
    @pytest.mark.asyncio
    async def test_mqtt_connection(self):
        """Test that we can connect to MQTT broker."""
        client = MQTTClient(
            hostname=MQTT_HOST,
            port=MQTT_PORT
        )
        try:
            await client.__aenter__()
            # If we get here without exception, connection succeeded
            assert client is not None
        finally:
            await client.__aexit__(None, None, None)
    
    @pytest.mark.asyncio
    async def test_mqtt_topic_validation(self):
        """Test that MQTT module validates topic names."""
        # Valid topic name
        valid_config = {
            "module": "mqtt",
            "topic": "valid/topic/name_123",
            "connection_details": {
                "host": MQTT_HOST,
                "port": MQTT_PORT
            }
        }
        module = MQTTModule(valid_config)
        assert module._validated_topic == "valid/topic/name_123"
        
        # Invalid topic name (contains wildcard)
        invalid_config = {
            "module": "mqtt",
            "topic": "topic/+/wildcard",
            "connection_details": {
                "host": MQTT_HOST,
                "port": MQTT_PORT
            }
        }
        with pytest.raises(ValueError, match="wildcard"):
            MQTTModule(invalid_config)
    
    @pytest.mark.asyncio
    async def test_mqtt_message_publishing(self, mqtt_consumer):
        """Test that we can publish messages to MQTT topics."""
        test_topic = f"{TEST_MQTT_TOPIC_PREFIX}message_test"
        
        # Create module
        config = {
            "module": "mqtt",
            "topic": test_topic,
            "connection_details": {
                "host": MQTT_HOST,
                "port": MQTT_PORT
            }
        }
        
        module = MQTTModule(config)
        
        # Test payload
        test_payload = {"event": "mqtt_test", "data": {"value": 123}}
        test_headers = {"X-Test": "integration"}
        
        # Subscribe to topic
        await mqtt_consumer.subscribe(test_topic)
        
        # Publish message
        await module.process(test_payload, test_headers)
        
        # Consume message (with timeout)
        try:
            async with mqtt_consumer.messages() as messages:
                message = await asyncio.wait_for(
                    messages.__anext__(),
                    timeout=5.0
                )
                
                # Verify message
                received_data = json.loads(message.payload.decode('utf-8'))
                assert received_data == test_payload
                assert message.topic.value == test_topic
                
        except asyncio.TimeoutError:
            pytest.fail("Message not received within timeout")
        finally:
            if module.client:
                await module.teardown()
    
    @pytest.mark.asyncio
    async def test_mqtt_qos_levels(self, mqtt_consumer):
        """Test publishing messages with different QoS levels."""
        for qos in [0, 1, 2]:
            test_topic = f"{TEST_MQTT_TOPIC_PREFIX}qos{qos}_test"
            
            config = {
                "module": "mqtt",
                "topic": test_topic,
                "connection_details": {
                    "host": MQTT_HOST,
                    "port": MQTT_PORT
                },
                "module-config": {
                    "qos": qos
                }
            }
            
            module = MQTTModule(config)
            
            test_payload = {"event": f"qos{qos}_test", "qos": qos}
            
            # Subscribe with matching QoS
            await mqtt_consumer.subscribe(test_topic, qos=qos)
            
            # Publish message
            await module.process(test_payload, {})
            
            # Consume message
            try:
                async with mqtt_consumer.messages() as messages:
                    message = await asyncio.wait_for(
                        messages.__anext__(),
                        timeout=5.0
                    )
                    
                    received_data = json.loads(message.payload.decode('utf-8'))
                    assert received_data == test_payload
                    assert message.qos == qos
                    
            except asyncio.TimeoutError:
                pytest.fail(f"Message not received within timeout for QoS {qos}")
            finally:
                if module.client:
                    await module.teardown()
    
    @pytest.mark.asyncio
    async def test_mqtt_retained_messages(self, mqtt_consumer):
        """Test retained message functionality."""
        test_topic = f"{TEST_MQTT_TOPIC_PREFIX}retained_test"
        
        config = {
            "module": "mqtt",
            "topic": test_topic,
            "connection_details": {
                "host": MQTT_HOST,
                "port": MQTT_PORT
            },
            "module-config": {
                "retained": True,
                "qos": 1
            }
        }
        
        module = MQTTModule(config)
        
        test_payload = {"event": "retained_test", "data": "retained_value"}
        
        # Publish retained message
        await module.process(test_payload, {})
        
        # Wait a bit for message to be retained
        await asyncio.sleep(0.5)
        
        # Subscribe after publishing (should receive retained message)
        await mqtt_consumer.subscribe(test_topic, qos=1)
        
        try:
            async with mqtt_consumer.messages() as messages:
                message = await asyncio.wait_for(
                    messages.__anext__(),
                    timeout=5.0
                )
                
                received_data = json.loads(message.payload.decode('utf-8'))
                assert received_data == test_payload
                # Note: aiomqtt may not expose retain flag directly, but message should be received
                
        except asyncio.TimeoutError:
            pytest.fail("Retained message not received within timeout")
        finally:
            if module.client:
                await module.teardown()
    
    @pytest.mark.asyncio
    async def test_mqtt_multiple_messages(self, mqtt_consumer):
        """Test publishing multiple messages to the same topic."""
        test_topic = f"{TEST_MQTT_TOPIC_PREFIX}multiple_test"
        
        config = {
            "module": "mqtt",
            "topic": test_topic,
            "connection_details": {
                "host": MQTT_HOST,
                "port": MQTT_PORT
            }
        }
        
        module = MQTTModule(config)
        
        # Subscribe
        await mqtt_consumer.subscribe(test_topic)
        
        # Publish multiple messages
        messages = []
        for i in range(5):
            payload = {"event": "multiple_test", "index": i, "data": {"value": i * 10}}
            await module.process(payload, {})
            messages.append(payload)
            await asyncio.sleep(0.1)  # Small delay between messages
        
        # Consume messages
        received_messages = []
        try:
            async with mqtt_consumer.messages() as messages_stream:
                for _ in range(5):
                    message = await asyncio.wait_for(
                        messages_stream.__anext__(),
                        timeout=5.0
                    )
                    received_data = json.loads(message.payload.decode('utf-8'))
                    received_messages.append(received_data)
        except asyncio.TimeoutError:
            pass
        
        # Verify we received all messages
        assert len(received_messages) >= 5
        
        # Verify message content
        for msg in received_messages:
            assert "event" in msg
            assert msg["event"] == "multiple_test"
            assert "index" in msg
        
        if module.client:
            await module.teardown()
    
    @pytest.mark.asyncio
    async def test_mqtt_connection_error_handling(self):
        """Test handling of connection failures."""
        # Try to connect to invalid broker
        config = {
            "module": "mqtt",
            "topic": "test_topic",
            "connection_details": {
                "host": "invalid_host",
                "port": 1883
            }
        }
        
        module = MQTTModule(config)
        
        # Process should raise connection error
        with pytest.raises(Exception, match="MQTT|connection|operation"):
            await module.process({"test": "data"}, {})
    
    @pytest.mark.asyncio
    async def test_mqtt_shelly_gen2_format(self, mqtt_consumer):
        """Test Shelly Gen2 JSON format compatibility."""
        test_topic = f"{TEST_MQTT_TOPIC_PREFIX}shelly/gen2/status"
        
        config = {
            "module": "mqtt",
            "topic": test_topic,
            "connection_details": {
                "host": MQTT_HOST,
                "port": MQTT_PORT
            },
            "module-config": {
                "shelly_gen2_format": True,
                "device_id": "shelly_device_123"
            }
        }
        
        module = MQTTModule(config)
        
        test_payload = {"relay": {"on": True}, "temperature": 25.5}
        
        # Subscribe
        await mqtt_consumer.subscribe(test_topic)
        
        # Publish message
        await module.process(test_payload, {})
        
        # Consume message
        try:
            async with mqtt_consumer.messages() as messages:
                message = await asyncio.wait_for(
                    messages.__anext__(),
                    timeout=5.0
                )
                
                received_data = json.loads(message.payload.decode('utf-8'))
                # Shelly Gen2 format should wrap payload
                assert "id" in received_data
                assert received_data["id"] == "shelly_device_123"
                assert "source" in received_data
                assert "params" in received_data
                
        except asyncio.TimeoutError:
            pytest.fail("Shelly Gen2 message not received within timeout")
        finally:
            if module.client:
                await module.teardown()
    
    @pytest.mark.asyncio
    async def test_mqtt_tasmota_cmnd_format(self, mqtt_consumer):
        """Test Tasmota command format compatibility."""
        config = {
            "module": "mqtt",
            "topic": "cmnd/test_device/POWER",  # Will be overridden by tasmota_format
            "connection_details": {
                "host": MQTT_HOST,
                "port": MQTT_PORT
            },
            "module-config": {
                "tasmota_format": True,
                "tasmota_type": "cmnd",
                "device_name": "test_device",
                "command": "POWER"
            }
        }
        
        module = MQTTModule(config)
        
        test_payload = {"POWER": "ON"}
        
        # Subscribe to the generated topic
        expected_topic = "cmnd/test_device/POWER"
        await mqtt_consumer.subscribe(expected_topic)
        
        # Publish message
        await module.process(test_payload, {})
        
        # Consume message
        try:
            async with mqtt_consumer.messages() as messages:
                message = await asyncio.wait_for(
                    messages.__anext__(),
                    timeout=5.0
                )
                
                received_data = json.loads(message.payload.decode('utf-8'))
                assert received_data == test_payload
                assert message.topic.value == expected_topic
                
        except asyncio.TimeoutError:
            pytest.fail("Tasmota command message not received within timeout")
        finally:
            if module.client:
                await module.teardown()
    
    @pytest.mark.asyncio
    async def test_mqtt_tasmota_stat_format(self, mqtt_consumer):
        """Test Tasmota status format compatibility."""
        config = {
            "module": "mqtt",
            "topic": "stat/test_device/status",
            "connection_details": {
                "host": MQTT_HOST,
                "port": MQTT_PORT
            },
            "module-config": {
                "tasmota_format": True,
                "tasmota_type": "stat",
                "device_name": "test_device"
            }
        }
        
        module = MQTTModule(config)
        
        test_payload = {"Status": {"Power": "ON", "Temperature": 22.5}}
        
        # Subscribe
        expected_topic = "stat/test_device/status"
        await mqtt_consumer.subscribe(expected_topic)
        
        # Publish message
        await module.process(test_payload, {})
        
        # Consume message
        try:
            async with mqtt_consumer.messages() as messages:
                message = await asyncio.wait_for(
                    messages.__anext__(),
                    timeout=5.0
                )
                
                received_data = json.loads(message.payload.decode('utf-8'))
                assert received_data == test_payload
                
        except asyncio.TimeoutError:
            pytest.fail("Tasmota status message not received within timeout")
        finally:
            if module.client:
                await module.teardown()
    
    @pytest.mark.asyncio
    async def test_mqtt_topic_prefix(self, mqtt_consumer):
        """Test topic prefix functionality."""
        config = {
            "module": "mqtt",
            "topic": "events",
            "connection_details": {
                "host": MQTT_HOST,
                "port": MQTT_PORT
            },
            "module-config": {
                "topic_prefix": "webhook/prefix"
            }
        }
        
        module = MQTTModule(config)
        
        test_payload = {"event": "test"}
        
        # Subscribe to prefixed topic
        expected_topic = "webhook/prefix/events"
        await mqtt_consumer.subscribe(expected_topic)
        
        # Publish message
        await module.process(test_payload, {})
        
        # Consume message
        try:
            async with mqtt_consumer.messages() as messages:
                message = await asyncio.wait_for(
                    messages.__anext__(),
                    timeout=5.0
                )
                
                assert message.topic.value == expected_topic
                received_data = json.loads(message.payload.decode('utf-8'))
                assert received_data == test_payload
                
        except asyncio.TimeoutError:
            pytest.fail("Prefixed topic message not received within timeout")
        finally:
            if module.client:
                await module.teardown()
    
    @pytest.mark.asyncio
    async def test_mqtt_producer_reuse(self, mqtt_consumer):
        """Test that client is reused across multiple calls."""
        test_topic = f"{TEST_MQTT_TOPIC_PREFIX}reuse_test"
        
        config = {
            "module": "mqtt",
            "topic": test_topic,
            "connection_details": {
                "host": MQTT_HOST,
                "port": MQTT_PORT
            }
        }
        
        module = MQTTModule(config)
        
        # First call should create client
        await module.process({"test": "first"}, {})
        client1 = module.client
        
        # Second call should reuse client
        await module.process({"test": "second"}, {})
        client2 = module.client
        
        # Should be the same client instance
        assert client1 is client2
        
        if module.client:
            await module.teardown()
    
    @pytest.mark.asyncio
    async def test_mqtt_message_format_json(self, mqtt_consumer):
        """Test JSON message format."""
        test_topic = f"{TEST_MQTT_TOPIC_PREFIX}format_json"
        
        config = {
            "module": "mqtt",
            "topic": test_topic,
            "connection_details": {
                "host": MQTT_HOST,
                "port": MQTT_PORT
            },
            "module-config": {
                "format": "json"
            }
        }
        
        module = MQTTModule(config)
        
        test_payload = {"event": "json_format", "data": {"nested": "value"}}
        
        await mqtt_consumer.subscribe(test_topic)
        await module.process(test_payload, {})
        
        try:
            async with mqtt_consumer.messages() as messages:
                message = await asyncio.wait_for(
                    messages.__anext__(),
                    timeout=5.0
                )
                
                received_data = json.loads(message.payload.decode('utf-8'))
                assert received_data == test_payload
                
        except asyncio.TimeoutError:
            pytest.fail("JSON format message not received within timeout")
        finally:
            if module.client:
                await module.teardown()
    
    @pytest.mark.asyncio
    async def test_mqtt_message_format_raw(self, mqtt_consumer):
        """Test raw message format."""
        test_topic = f"{TEST_MQTT_TOPIC_PREFIX}format_raw"
        
        config = {
            "module": "mqtt",
            "topic": test_topic,
            "connection_details": {
                "host": MQTT_HOST,
                "port": MQTT_PORT
            },
            "module-config": {
                "format": "raw"
            }
        }
        
        module = MQTTModule(config)
        
        test_payload = "raw string payload"
        
        await mqtt_consumer.subscribe(test_topic)
        await module.process(test_payload, {})
        
        try:
            async with mqtt_consumer.messages() as messages:
                message = await asyncio.wait_for(
                    messages.__anext__(),
                    timeout=5.0
                )
                
                received_data = message.payload.decode('utf-8')
                assert received_data == test_payload
                
        except asyncio.TimeoutError:
            pytest.fail("Raw format message not received within timeout")
        finally:
            if module.client:
                await module.teardown()

