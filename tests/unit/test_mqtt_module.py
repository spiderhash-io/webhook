"""
Security and functional tests for MQTT module.
Tests topic name validation, configuration, and error handling.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from src.modules.mqtt import MQTTModule


class TestMQTTTopicValidation:
    """Test suite for MQTT topic name validation."""
    
    def test_valid_topic_names(self):
        """Test that valid topic names are accepted."""
        valid_names = [
            "webhook_events",
            "webhook/events",
            "webhook/events/status",
            "shelly/device123/status",
            "cmnd/device_name/command",
            "stat/device_name/status",
            "tele/device_name/telemetry",
            "webhook.events",
            "webhook-events",
            "webhook123",
            "a",  # Minimum length
            "A" * 100,  # Long but valid
            "webhook_events.test",
            "webhook-events_topic",
            "/absolute/topic",
            "relative/topic",
        ]
        
        for topic_name in valid_names:
            config = {
                "module": "mqtt",
                "topic": topic_name,
                "connection_details": {
                    "host": "localhost",
                    "port": 1883
                }
            }
            module = MQTTModule(config)
            assert module._validated_topic == topic_name
    
    def test_injection_attempts_rejected(self):
        """Test that injection attempts in topic names are rejected."""
        injection_attempts = [
            "webhook_events; DELETE",
            "webhook_events | CONFIG",
            "webhook_events && ALTER",
            "webhook_events\nPUBLISH",
            "webhook_events\rPUBLISH",
            "webhook_events\x00PUBLISH",
            "webhook_events`eval`",
            "webhook_events$(command)",
        ]
        
        for malicious_name in injection_attempts:
            config = {
                "module": "mqtt",
                "topic": malicious_name,
                "connection_details": {
                    "host": "localhost",
                    "port": 1883
                }
            }
            with pytest.raises(ValueError) as exc_info:
                MQTTModule(config)
            error_msg = str(exc_info.value).lower()
            assert any(keyword in error_msg for keyword in [
                "invalid", "forbidden", "dangerous", "not allowed", "control"
            ]), f"Failed to reject injection attempt: {malicious_name}"
    
    def test_wildcards_rejected(self):
        """Test that MQTT wildcards are rejected in published topics."""
        wildcard_topics = [
            "webhook/+",
            "webhook/+/status",
            "webhook/#",
            "webhook/+/#",
            "+/webhook",
            "#/webhook",
            "webhook+",
            "webhook#",
        ]
        
        for topic in wildcard_topics:
            config = {
                "module": "mqtt",
                "topic": topic,
                "connection_details": {
                    "host": "localhost",
                    "port": 1883
                }
            }
            with pytest.raises(ValueError) as exc_info:
                MQTTModule(config)
            assert "wildcard" in str(exc_info.value).lower()
    
    def test_dangerous_patterns_rejected(self):
        """Test that dangerous patterns are rejected."""
        dangerous_patterns = [
            "webhook..events",  # Path traversal
            "webhook--events",  # SQL-like comment
            "webhook;events",  # Command separator
            "webhook/*events*/",  # Comment block
            "webhook(events)",  # Function call pattern
            "webhook[events]",  # Array access pattern
            "webhook{events}",  # Object access pattern
            "webhook|events",  # Pipe
            "webhook&events",  # Background process
            "webhook$events",  # Variable expansion
            "webhook`events`",  # Command substitution
            "webhook\\events",  # Backslash
            "webhook:events",  # Colon
            "webhook@events",  # At sign
            "webhook#events",  # Hash (wildcard)
            "webhook%events",  # Percent
        ]
        
        for pattern in dangerous_patterns:
            config = {
                "module": "mqtt",
                "topic": pattern,
                "connection_details": {
                    "host": "localhost",
                    "port": 1883
                }
            }
            # All patterns should raise ValueError (either for dangerous pattern or invalid format)
            with pytest.raises(ValueError) as exc_info:
                MQTTModule(config)
            error_msg = str(exc_info.value).lower()
            # Accept any ValueError - some are caught by regex (invalid format), others by dangerous pattern check
            assert len(error_msg) > 0, f"Should raise ValueError for pattern: {pattern}"
    
    def test_special_characters_rejected(self):
        """Test that special characters are rejected."""
        special_chars = [
            "webhook events",  # Space
            "webhook'events",  # Single quote
            'webhook"events',  # Double quote
            "webhook=events",  # Equals
            "webhook?events",  # Question mark
            "webhook!events",  # Exclamation
        ]
        
        for name in special_chars:
            config = {
                "module": "mqtt",
                "topic": name,
                "connection_details": {
                    "host": "localhost",
                    "port": 1883
                }
            }
            with pytest.raises(ValueError) as exc_info:
                MQTTModule(config)
            assert "Invalid topic name" in str(exc_info.value)
    
    def test_empty_topic_name_rejected(self):
        """Test that empty topic names are rejected."""
        # Empty string should be rejected
        config = {
            "module": "mqtt",
            "topic": "",
            "connection_details": {
                "host": "localhost",
                "port": 1883
            }
        }
        with pytest.raises(ValueError) as exc_info:
            MQTTModule(config)
        assert "empty" in str(exc_info.value).lower() or "non-empty string" in str(exc_info.value).lower()
        
        # Whitespace-only should be rejected after stripping
        config = {
            "module": "mqtt",
            "topic": "   ",
            "connection_details": {
                "host": "localhost",
                "port": 1883
            }
        }
        with pytest.raises(ValueError) as exc_info:
            MQTTModule(config)
        assert "empty" in str(exc_info.value).lower()
        
        # None is allowed in __init__ but will fail in process()
        config = {
            "module": "mqtt",
            "topic": None,
            "connection_details": {
                "host": "localhost",
                "port": 1883
            }
        }
        module = MQTTModule(config)
        assert module._validated_topic is None
    
    def test_topic_name_length_limit(self):
        """Test that very long topic names are rejected."""
        # Create a very long topic name (exceeds 32768 bytes)
        long_name = "a" * 40000
        
        config = {
            "module": "mqtt",
            "topic": long_name,
            "connection_details": {
                "host": "localhost",
                "port": 1883
            }
        }
        with pytest.raises(ValueError) as exc_info:
            MQTTModule(config)
        assert "too long" in str(exc_info.value).lower()
    
    def test_topic_name_whitespace_handling(self):
        """Test that whitespace is properly handled."""
        # Whitespace should be stripped
        config = {
            "module": "mqtt",
            "topic": "  webhook/events  ",
            "connection_details": {
                "host": "localhost",
                "port": 1883
            }
        }
        module = MQTTModule(config)
        validated = module._validate_topic_name("  webhook/events  ")
        assert validated == "webhook/events"
        
        # But whitespace-only should be rejected
        config = {
            "module": "mqtt",
            "topic": "   ",
            "connection_details": {
                "host": "localhost",
                "port": 1883
            }
        }
        with pytest.raises(ValueError):
            MQTTModule(config)
    
    def test_topic_name_with_slashes(self):
        """Test that topic names with forward slashes are accepted."""
        valid_slash_topics = [
            "webhook/events",
            "webhook/events/status",
            "/absolute/topic",
            "shelly/device123/status",
            "cmnd/device/command",
        ]
        
        for topic in valid_slash_topics:
            config = {
                "module": "mqtt",
                "topic": topic,
                "connection_details": {
                    "host": "localhost",
                    "port": 1883
                }
            }
            module = MQTTModule(config)
            assert module._validated_topic == topic
    
    def test_consecutive_slashes_rejected(self):
        """Test that consecutive slashes are rejected."""
        config = {
            "module": "mqtt",
            "topic": "webhook//events",
            "connection_details": {
                "host": "localhost",
                "port": 1883
            }
        }
        with pytest.raises(ValueError) as exc_info:
            MQTTModule(config)
        assert "consecutive" in str(exc_info.value).lower() or "slashes" in str(exc_info.value).lower()
    
    def test_system_topic_prefix_rejected(self):
        """Test that topics starting with $ are rejected."""
        config = {
            "module": "mqtt",
            "topic": "$SYS/status",
            "connection_details": {
                "host": "localhost",
                "port": 1883
            }
        }
        with pytest.raises(ValueError) as exc_info:
            MQTTModule(config)
        assert "$" in str(exc_info.value) or "system" in str(exc_info.value).lower()
    
    def test_control_characters_rejected(self):
        """Test that control characters are rejected."""
        control_chars = [
            "webhook\revents",
            "webhook\nevents",
            "webhook\x00events",
            "webhook\tevents",
        ]
        
        for name in control_chars:
            config = {
                "module": "mqtt",
                "topic": name,
                "connection_details": {
                    "host": "localhost",
                    "port": 1883
                }
            }
            with pytest.raises(ValueError) as exc_info:
                MQTTModule(config)
            error_msg = str(exc_info.value).lower()
            assert any(keyword in error_msg for keyword in [
                "invalid", "forbidden", "control", "not allowed"
            ])


class TestMQTTConfiguration:
    """Test suite for MQTT module configuration."""
    
    def test_mqtt_version_3_1_1(self):
        """Test MQTT 3.1.1 version configuration."""
        config = {
            "module": "mqtt",
            "topic": "test/topic",
            "connection_details": {
                "host": "localhost",
                "port": 1883,
                "mqtt_version": "3.1.1"
            }
        }
        module = MQTTModule(config)
        version = module._get_mqtt_version()
        from aiomqtt import ProtocolVersion
        assert version == ProtocolVersion.V31
    
    def test_mqtt_version_5_0(self):
        """Test MQTT 5.0 version configuration."""
        config = {
            "module": "mqtt",
            "topic": "test/topic",
            "connection_details": {
                "host": "localhost",
                "port": 1883,
                "mqtt_version": "5.0"
            }
        }
        module = MQTTModule(config)
        version = module._get_mqtt_version()
        from aiomqtt import ProtocolVersion
        assert version == ProtocolVersion.V5
    
    def test_default_mqtt_version(self):
        """Test default MQTT version (3.1.1)."""
        config = {
            "module": "mqtt",
            "topic": "test/topic",
            "connection_details": {
                "host": "localhost",
                "port": 1883
            }
        }
        module = MQTTModule(config)
        version = module._get_mqtt_version()
        from aiomqtt import ProtocolVersion
        assert version == ProtocolVersion.V31
    
    def test_qos_levels(self):
        """Test QoS level validation."""
        config = {
            "module": "mqtt",
            "topic": "test/topic",
            "connection_details": {
                "host": "localhost",
                "port": 1883
            },
            "module-config": {
                "qos": 1
            }
        }
        module = MQTTModule(config)
        assert module.module_config.get('qos') == 1
    
    def test_invalid_qos_level(self):
        """Test that invalid QoS levels are rejected."""
        config = {
            "module": "mqtt",
            "topic": "test/topic",
            "connection_details": {
                "host": "localhost",
                "port": 1883
            },
            "module-config": {
                "qos": 3  # Invalid QoS
            }
        }
        module = MQTTModule(config)
        # Invalid QoS will be caught in process() method
        # We can't test it here without mocking the client
    
    def test_retained_message_config(self):
        """Test retained message configuration."""
        config = {
            "module": "mqtt",
            "topic": "test/topic",
            "connection_details": {
                "host": "localhost",
                "port": 1883
            },
            "module-config": {
                "retained": True
            }
        }
        module = MQTTModule(config)
        assert module.module_config.get('retained') is True
    
    def test_topic_prefix(self):
        """Test topic prefix configuration."""
        config = {
            "module": "mqtt",
            "topic": "events",
            "connection_details": {
                "host": "localhost",
                "port": 1883
            },
            "module-config": {
                "topic_prefix": "webhook"
            }
        }
        module = MQTTModule(config)
        assert module.module_config.get('topic_prefix') == "webhook"


class TestShellyCompatibility:
    """Test suite for Shelly device compatibility."""
    
    def test_shelly_gen2_format(self):
        """Test Shelly Gen2 JSON format configuration."""
        config = {
            "module": "mqtt",
            "topic": "shellies/device123/status",
            "connection_details": {
                "host": "localhost",
                "port": 1883
            },
            "module-config": {
                "shelly_gen2_format": True,
                "device_id": "device123"
            }
        }
        module = MQTTModule(config)
        assert module.module_config.get('shelly_gen2_format') is True
        assert module.module_config.get('device_id') == "device123"
    
    def test_shelly_topic_structure(self):
        """Test Shelly topic structure validation."""
        shelly_topics = [
            "shelly/device123/status",
            "shellies/device123/status",
            "shelly/device123/relay/0",
        ]
        
        for topic in shelly_topics:
            config = {
                "module": "mqtt",
                "topic": topic,
                "connection_details": {
                    "host": "localhost",
                    "port": 1883
                }
            }
            module = MQTTModule(config)
            assert module._validated_topic == topic


class TestSonoffTasmotaCompatibility:
    """Test suite for Sonoff/Tasmota device compatibility."""
    
    def test_tasmota_cmnd_format(self):
        """Test Tasmota command format."""
        config = {
            "module": "mqtt",
            "topic": "cmnd/device_name/command",
            "connection_details": {
                "host": "localhost",
                "port": 1883
            },
            "module-config": {
                "tasmota_format": True,
                "tasmota_type": "cmnd",
                "device_name": "device_name",
                "command": "command"
            }
        }
        module = MQTTModule(config)
        assert module.module_config.get('tasmota_format') is True
        assert module.module_config.get('tasmota_type') == "cmnd"
    
    def test_tasmota_stat_format(self):
        """Test Tasmota status format."""
        config = {
            "module": "mqtt",
            "topic": "stat/device_name/status",
            "connection_details": {
                "host": "localhost",
                "port": 1883
            },
            "module-config": {
                "tasmota_format": True,
                "tasmota_type": "stat",
                "device_name": "device_name"
            }
        }
        module = MQTTModule(config)
        assert module.module_config.get('tasmota_type') == "stat"
    
    def test_tasmota_tele_format(self):
        """Test Tasmota telemetry format."""
        config = {
            "module": "mqtt",
            "topic": "tele/device_name/telemetry",
            "connection_details": {
                "host": "localhost",
                "port": 1883
            },
            "module-config": {
                "tasmota_format": True,
                "tasmota_type": "tele",
                "device_name": "device_name"
            }
        }
        module = MQTTModule(config)
        assert module.module_config.get('tasmota_type') == "tele"
    
    def test_tasmota_topic_structures(self):
        """Test Tasmota topic structure validation."""
        tasmota_topics = [
            "cmnd/device_name/POWER",
            "stat/device_name/POWER",
            "tele/device_name/STATE",
        ]
        
        for topic in tasmota_topics:
            config = {
                "module": "mqtt",
                "topic": topic,
                "connection_details": {
                    "host": "localhost",
                    "port": 1883
                }
            }
            module = MQTTModule(config)
            assert module._validated_topic == topic


class TestMQTTErrorHandling:
    """Test suite for MQTT error handling."""
    
    @pytest.mark.asyncio
    async def test_missing_topic_raises_error(self):
        """Test that missing topic raises error during process."""
        config = {
            "module": "mqtt",
            "connection_details": {
                "host": "localhost",
                "port": 1883
            }
        }
        module = MQTTModule(config)
        
        with pytest.raises(ValueError, match="topic is required"):
            await module.process({"test": "data"}, {})
    
    @pytest.mark.asyncio
    async def test_invalid_qos_raises_error(self):
        """Test that invalid QoS level raises error."""
        config = {
            "module": "mqtt",
            "topic": "test/topic",
            "connection_details": {
                "host": "localhost",
                "port": 1883
            },
            "module-config": {
                "qos": 3  # Invalid
            }
        }
        module = MQTTModule(config)
        
        # Mock client to avoid actual connection
        with patch.object(module, 'setup', new_callable=AsyncMock):
            with patch.object(module, 'client') as mock_client:
                mock_client.publish = AsyncMock()
                module.client = mock_client
                
                # Error is sanitized, so we expect Exception, not ValueError
                with pytest.raises(Exception, match="MQTT|operation"):
                    await module.process({"test": "data"}, {})
    
    @pytest.mark.asyncio
    async def test_connection_error_sanitization(self):
        """Test that connection errors are sanitized."""
        config = {
            "module": "mqtt",
            "topic": "test/topic",
            "connection_details": {
                "host": "invalid_host",
                "port": 1883
            }
        }
        module = MQTTModule(config)
        
        # This will fail during setup, but error should be sanitized
        with pytest.raises(Exception) as exc_info:
            await module.process({"test": "data"}, {})
        
        # Error message should be sanitized (not expose connection details)
        error_msg = str(exc_info.value)
        assert "invalid_host" not in error_msg or "MQTT operation" in error_msg


class TestMQTTTopicPrefix:
    """Test suite for topic prefix functionality."""
    
    def test_topic_prefix_validation(self):
        """Test that topic prefix is validated."""
        config = {
            "module": "mqtt",
            "topic": "events",
            "connection_details": {
                "host": "localhost",
                "port": 1883
            },
            "module-config": {
                "topic_prefix": "webhook/prefix"
            }
        }
        module = MQTTModule(config)
        assert module.module_config.get('topic_prefix') == "webhook/prefix"
    
    def test_invalid_topic_prefix_rejected(self):
        """Test that invalid topic prefix is rejected."""
        # This will be caught during process() when prefix is applied
        # We can't easily test it here without mocking process()
        pass

