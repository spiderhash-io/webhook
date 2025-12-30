"""
Security tests for Kafka module topic name injection prevention.
Tests topic name validation to prevent injection attacks.
"""
import pytest
from src.modules.kafka import KafkaModule


class TestKafkaTopicInjection:
    """Test suite for Kafka topic name injection prevention."""
    
    def test_valid_topic_names(self):
        """Test that valid topic names are accepted."""
        valid_names = [
            "webhook_events",
            "webhook_events_2024",
            "webhook-events",
            "webhook.events",
            "webhook123",
            "ab",  # Minimum length
            "A" * 100,  # Long but valid
            "webhook_events.test",
            "webhook-events_topic",
        ]
        
        for topic_name in valid_names:
            config = {
                "module": "kafka",
                "topic": topic_name
            }
            module = KafkaModule(config)
            assert module._validate_topic_name(topic_name) == topic_name
    
    def test_injection_attempts_rejected(self):
        """Test that injection attempts in topic names are rejected."""
        injection_attempts = [
            "webhook_events; DELETE",
            "webhook_events | CONFIG",
            "webhook_events && ALTER",
            "webhook_events\nPRODUCE",
            "webhook_events\rPRODUCE",
            "webhook_events\x00PRODUCE",
            "webhook_events`eval`",
            "webhook_events$(command)",
        ]
        
        for malicious_name in injection_attempts:
            config = {
                "module": "kafka",
                "topic": malicious_name
            }
            with pytest.raises(ValueError) as exc_info:
                KafkaModule(config)
            error_msg = str(exc_info.value).lower()
            assert any(keyword in error_msg for keyword in [
                "invalid", "forbidden", "dangerous", "not allowed", "control"
            ]), f"Failed to reject injection attempt: {malicious_name}"
    
    def test_kafka_keywords_rejected(self):
        """Test that Kafka command keywords in topic names are rejected."""
        kafka_keywords = [
            "create",
            "delete",
            "describe",
            "list",
            "alter",
            "config",
            "produce",
            "consume",
        ]
        
        for keyword in kafka_keywords:
            # Test as exact match
            config = {
                "module": "kafka",
                "topic": keyword
            }
            with pytest.raises(ValueError) as exc_info:
                KafkaModule(config)
            assert "forbidden" in str(exc_info.value).lower() or "keyword" in str(exc_info.value).lower()
    
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
            "webhook/events",  # Forward slash
            "webhook:events",  # Colon
            "webhook@events",  # At sign
            "webhook#events",  # Hash
            "webhook%events",  # Percent
        ]
        
        for pattern in dangerous_patterns:
            config = {
                "module": "kafka",
                "topic": pattern
            }
            with pytest.raises(ValueError) as exc_info:
                KafkaModule(config)
            error_msg = str(exc_info.value).lower()
            assert any(keyword in error_msg for keyword in [
                "invalid", "forbidden", "dangerous", "not allowed"
            ]), f"Failed to reject dangerous pattern: {pattern}"
    
    def test_special_characters_rejected(self):
        """Test that special characters are rejected."""
        special_chars = [
            "webhook events",  # Space
            "webhook'events",  # Single quote
            'webhook"events',  # Double quote
            "webhook+events",  # Plus (not in allowed set)
            "webhook=events",  # Equals
            "webhook?events",  # Question mark
            "webhook!events",  # Exclamation
        ]
        
        for name in special_chars:
            config = {
                "module": "kafka",
                "topic": name
            }
            with pytest.raises(ValueError) as exc_info:
                KafkaModule(config)
            assert "Invalid topic name" in str(exc_info.value)
    
    def test_unicode_characters_rejected(self):
        """Test that Unicode characters are rejected."""
        unicode_names = [
            "webhook_测试_events",
            "webhook_ログ",
            "webhook_логи",
            "webhook_📊_events",
        ]
        
        for name in unicode_names:
            config = {
                "module": "kafka",
                "topic": name
            }
            with pytest.raises(ValueError) as exc_info:
                KafkaModule(config)
            assert "Invalid topic name" in str(exc_info.value)
    
    def test_empty_topic_name_rejected(self):
        """Test that empty topic names are rejected."""
        # Empty string and whitespace-only should be rejected during validation
        empty_names = ["", "   "]
        
        for name in empty_names:
            config = {
                "module": "kafka",
                "topic": name
            }
            with pytest.raises(ValueError) as exc_info:
                KafkaModule(config)
            assert "empty" in str(exc_info.value).lower() or "non-empty string" in str(exc_info.value).lower()
        
        # None is allowed in __init__ but will fail in process()
        config = {
            "module": "kafka",
            "topic": None
        }
        module = KafkaModule(config)
        assert module._validated_topic is None
    
    def test_topic_name_length_limit(self):
        """Test that very long topic names are rejected."""
        # Create a very long but valid topic name
        long_name = "a" * 300  # Exceeds 249 character limit
        
        config = {
            "module": "kafka",
            "topic": long_name
        }
        with pytest.raises(ValueError) as exc_info:
            KafkaModule(config)
        assert "too long" in str(exc_info.value).lower()
    
    def test_topic_name_minimum_length(self):
        """Test that topic names that are too short are rejected."""
        # Single character should be rejected
        config = {
            "module": "kafka",
            "topic": "a"
        }
        with pytest.raises(ValueError) as exc_info:
            KafkaModule(config)
        assert "too short" in str(exc_info.value).lower()
    
    def test_topic_name_whitespace_handling(self):
        """Test that whitespace is properly handled."""
        # Whitespace should be stripped
        config = {
            "module": "kafka",
            "topic": "  webhook_events  "
        }
        module = KafkaModule(config)
        validated = module._validate_topic_name("  webhook_events  ")
        assert validated == "webhook_events"
        
        # But whitespace-only should be rejected
        config = {
            "module": "kafka",
            "topic": "   "
        }
        with pytest.raises(ValueError):
            KafkaModule(config)
    
    def test_topic_name_case_sensitivity(self):
        """Test that topic names are case-sensitive (preserved)."""
        config = {
            "module": "kafka",
            "topic": "WebhookEvents"
        }
        module = KafkaModule(config)
        validated = module._validate_topic_name("WebhookEvents")
        assert validated == "WebhookEvents"
    
    def test_topic_name_with_numbers(self):
        """Test that topic names with numbers are accepted."""
        config = {
            "module": "kafka",
            "topic": "webhook_events_2024_01"
        }
        module = KafkaModule(config)
        validated = module._validate_topic_name("webhook_events_2024_01")
        assert validated == "webhook_events_2024_01"
    
    def test_topic_name_underscore_hyphen_dot(self):
        """Test edge cases with underscores, hyphens, and dots."""
        valid_names = [
            "webhook__events",  # Double underscore
            "webhook.events.test",  # Multiple dots
            "webhook-events-test",  # Multiple hyphens
            "webhook_events_test",  # Multiple underscores
        ]
        
        for name in valid_names:
            config = {
                "module": "kafka",
                "topic": name
            }
            module = KafkaModule(config)
            validated = module._validate_topic_name(name)
            assert validated == name
        
        # Double hyphen and double dot should be rejected
        invalid_names = [
            "webhook--events",  # Double hyphen
            "webhook..events",  # Double dot
        ]
        
        for name in invalid_names:
            config = {
                "module": "kafka",
                "topic": name
            }
            with pytest.raises(ValueError):
                KafkaModule(config)
    
    def test_topic_name_starts_with_number(self):
        """Test that topic names starting with numbers are accepted."""
        config = {
            "module": "kafka",
            "topic": "2024_webhook_events"
        }
        module = KafkaModule(config)
        validated = module._validate_topic_name("2024_webhook_events")
        assert validated == "2024_webhook_events"
    
    def test_control_characters_rejected(self):
        """Test that control characters are rejected."""
        control_chars = [
            "webhook\revents",  # Carriage return
            "webhook\nevents",  # Newline
            "webhook\x00events",  # Null byte
            "webhook\tevents",  # Tab
        ]
        
        for name in control_chars:
            config = {
                "module": "kafka",
                "topic": name
            }
            with pytest.raises(ValueError) as exc_info:
                KafkaModule(config)
            error_msg = str(exc_info.value).lower()
            assert any(keyword in error_msg for keyword in [
                "invalid", "forbidden", "control", "not allowed"
            ])
    
    def test_kafka_command_injection_patterns(self):
        """Test various Kafka command injection patterns."""
        injection_patterns = [
            ("webhook; DELETE", "command separator"),
            ("webhook | CONFIG", "pipe to command"),
            ("webhook && ALTER", "logical AND"),
            ("webhook || DESCRIBE", "logical OR"),
            ("webhook`eval`", "command substitution"),
            ("webhook$(command)", "command expansion"),
            ("webhook\nPRODUCE", "newline injection"),
            ("webhook\rPRODUCE", "carriage return injection"),
        ]
        
        for pattern, description in injection_patterns:
            config = {
                "module": "kafka",
                "topic": pattern
            }
            with pytest.raises(ValueError) as exc_info:
                KafkaModule(config)
            error_msg = str(exc_info.value).lower()
            assert any(keyword in error_msg for keyword in [
                "invalid", "forbidden", "dangerous", "not allowed", "control"
            ]), f"Failed to reject injection pattern: {description}"
    
    def test_missing_topic_name_handled(self):
        """Test that missing topic name is handled gracefully."""
        config = {
            "module": "kafka"
            # No topic specified
        }
        module = KafkaModule(config)
        assert module._validated_topic is None
        
        # Should raise error when trying to process
        # (This would be caught in process() method)

