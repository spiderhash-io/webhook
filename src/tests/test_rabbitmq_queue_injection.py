"""
Security tests for RabbitMQ module queue name injection prevention.
Tests queue name validation to prevent injection attacks.
"""
import pytest
from src.modules.rabbitmq_module import RabbitMQModule


class TestRabbitMQQueueInjection:
    """Test suite for RabbitMQ queue name injection prevention."""
    
    def test_valid_queue_names(self):
        """Test that valid queue names are accepted."""
        valid_names = [
            "webhook_events",
            "webhook_events_2024",
            "webhook-events",
            "webhook.events",
            "webhook:events",
            "webhook123",
            "a",
            "A" * 100,  # Long but valid
            "webhook_events.test",
            "webhook-events_test:queue",
        ]
        
        for queue_name in valid_names:
            config = {
                "module": "rabbitmq",
                "queue_name": queue_name
            }
            module = RabbitMQModule(config)
            assert module._validate_queue_name(queue_name) == queue_name
    
    def test_injection_attempts_rejected(self):
        """Test that injection attempts in queue names are rejected."""
        injection_attempts = [
            "webhook_events; DELETE",
            "webhook_events | BIND",
            "webhook_events && PURGE",
            "webhook_events\nDECLARE",
            "webhook_events\rDECLARE",
            "webhook_events\x00DECLARE",
            "webhook_events`eval`",
            "webhook_events$(command)",
        ]
        
        for malicious_name in injection_attempts:
            config = {
                "module": "rabbitmq",
                "queue_name": malicious_name
            }
            with pytest.raises(ValueError) as exc_info:
                RabbitMQModule(config)
            error_msg = str(exc_info.value).lower()
            assert any(keyword in error_msg for keyword in [
                "invalid", "forbidden", "dangerous", "not allowed", "control"
            ]), f"Failed to reject injection attempt: {malicious_name}"
    
    def test_rabbitmq_keywords_rejected(self):
        """Test that RabbitMQ command keywords in queue names are rejected."""
        rabbitmq_keywords = [
            "declare",
            "bind",
            "unbind",
            "delete",
            "purge",
            "get",
            "ack",
            "consume",
            "publish",
        ]
        
        for keyword in rabbitmq_keywords:
            # Test as exact match
            config = {
                "module": "rabbitmq",
                "queue_name": keyword
            }
            with pytest.raises(ValueError) as exc_info:
                RabbitMQModule(config)
            assert "forbidden" in str(exc_info.value).lower() or "keyword" in str(exc_info.value).lower()
    
    def test_amq_reserved_prefix_rejected(self):
        """Test that queue names starting with 'amq.' are rejected."""
        amq_names = [
            "amq.default",
            "amq.direct",
            "amq.topic",
            "amq.fanout",
            "amq.headers",
            "amq.test",
        ]
        
        for name in amq_names:
            config = {
                "module": "rabbitmq",
                "queue_name": name
            }
            with pytest.raises(ValueError) as exc_info:
                RabbitMQModule(config)
            assert "amq." in str(exc_info.value).lower() or "reserved" in str(exc_info.value).lower()
    
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
        ]
        
        for pattern in dangerous_patterns:
            config = {
                "module": "rabbitmq",
                "queue_name": pattern
            }
            with pytest.raises(ValueError) as exc_info:
                RabbitMQModule(config)
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
            "webhook@events",  # At sign
            "webhook#events",  # Hash
            "webhook%events",  # Percent
            "webhook+events",  # Plus (not in allowed set)
            "webhook=events",  # Equals
            "webhook?events",  # Question mark
            "webhook!events",  # Exclamation
        ]
        
        for name in special_chars:
            config = {
                "module": "rabbitmq",
                "queue_name": name
            }
            with pytest.raises(ValueError) as exc_info:
                RabbitMQModule(config)
            assert "Invalid queue name" in str(exc_info.value)
    
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
                "module": "rabbitmq",
                "queue_name": name
            }
            with pytest.raises(ValueError) as exc_info:
                RabbitMQModule(config)
            assert "Invalid queue name" in str(exc_info.value)
    
    def test_empty_queue_name_rejected(self):
        """Test that empty queue names are rejected."""
        # Empty string and whitespace-only should be rejected during validation
        empty_names = ["", "   "]
        
        for name in empty_names:
            config = {
                "module": "rabbitmq",
                "queue_name": name
            }
            with pytest.raises(ValueError) as exc_info:
                RabbitMQModule(config)
            assert "empty" in str(exc_info.value).lower() or "non-empty string" in str(exc_info.value).lower()
        
        # None is allowed in __init__ but will fail in process()
        config = {
            "module": "rabbitmq",
            "queue_name": None
        }
        module = RabbitMQModule(config)
        assert module._validated_queue_name is None
    
    def test_queue_name_length_limit(self):
        """Test that very long queue names are rejected."""
        # Create a very long but valid queue name
        long_name = "a" * 300  # Exceeds 255 character limit
        
        config = {
            "module": "rabbitmq",
            "queue_name": long_name
        }
        with pytest.raises(ValueError) as exc_info:
            RabbitMQModule(config)
        assert "too long" in str(exc_info.value).lower()
    
    def test_queue_name_whitespace_handling(self):
        """Test that whitespace is properly handled."""
        # Whitespace should be stripped
        config = {
            "module": "rabbitmq",
            "queue_name": "  webhook_events  "
        }
        module = RabbitMQModule(config)
        validated = module._validate_queue_name("  webhook_events  ")
        assert validated == "webhook_events"
        
        # But whitespace-only should be rejected
        config = {
            "module": "rabbitmq",
            "queue_name": "   "
        }
        with pytest.raises(ValueError):
            RabbitMQModule(config)
    
    def test_queue_name_case_sensitivity(self):
        """Test that queue names are case-sensitive (preserved)."""
        config = {
            "module": "rabbitmq",
            "queue_name": "WebhookEvents"
        }
        module = RabbitMQModule(config)
        validated = module._validate_queue_name("WebhookEvents")
        assert validated == "WebhookEvents"
    
    def test_queue_name_with_numbers(self):
        """Test that queue names with numbers are accepted."""
        config = {
            "module": "rabbitmq",
            "queue_name": "webhook_events_2024_01"
        }
        module = RabbitMQModule(config)
        validated = module._validate_queue_name("webhook_events_2024_01")
        assert validated == "webhook_events_2024_01"
    
    def test_queue_name_underscore_hyphen_dot_colon(self):
        """Test edge cases with underscores, hyphens, dots, and colons."""
        valid_names = [
            "webhook__events",  # Double underscore
            "webhook.events.test",  # Multiple dots
            "webhook-events-test",  # Multiple hyphens
            "webhook:events:queue",  # Multiple colons
            "webhook_events_test",  # Multiple underscores
        ]
        
        for name in valid_names:
            config = {
                "module": "rabbitmq",
                "queue_name": name
            }
            module = RabbitMQModule(config)
            validated = module._validate_queue_name(name)
            assert validated == name
        
        # Double hyphen and double dot should be rejected
        invalid_names = [
            "webhook--events",  # Double hyphen
            "webhook..events",  # Double dot
        ]
        
        for name in invalid_names:
            config = {
                "module": "rabbitmq",
                "queue_name": name
            }
            with pytest.raises(ValueError):
                RabbitMQModule(config)
    
    def test_queue_name_starts_with_number(self):
        """Test that queue names starting with numbers are accepted."""
        config = {
            "module": "rabbitmq",
            "queue_name": "2024_webhook_events"
        }
        module = RabbitMQModule(config)
        validated = module._validate_queue_name("2024_webhook_events")
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
                "module": "rabbitmq",
                "queue_name": name
            }
            with pytest.raises(ValueError) as exc_info:
                RabbitMQModule(config)
            error_msg = str(exc_info.value).lower()
            assert any(keyword in error_msg for keyword in [
                "invalid", "forbidden", "control", "not allowed"
            ])
    
    def test_rabbitmq_command_injection_patterns(self):
        """Test various RabbitMQ command injection patterns."""
        injection_patterns = [
            ("webhook; DELETE", "command separator"),
            ("webhook | BIND", "pipe to command"),
            ("webhook && PURGE", "logical AND"),
            ("webhook || DECLARE", "logical OR"),
            ("webhook`eval`", "command substitution"),
            ("webhook$(command)", "command expansion"),
            ("webhook\nDECLARE", "newline injection"),
            ("webhook\rDECLARE", "carriage return injection"),
        ]
        
        for pattern, description in injection_patterns:
            config = {
                "module": "rabbitmq",
                "queue_name": pattern
            }
            with pytest.raises(ValueError) as exc_info:
                RabbitMQModule(config)
            error_msg = str(exc_info.value).lower()
            assert any(keyword in error_msg for keyword in [
                "invalid", "forbidden", "dangerous", "not allowed", "control"
            ]), f"Failed to reject injection pattern: {description}"
    
    def test_missing_queue_name_handled(self):
        """Test that missing queue name is handled gracefully."""
        config = {
            "module": "rabbitmq"
            # No queue_name specified
        }
        module = RabbitMQModule(config)
        assert module._validated_queue_name is None
        
        # Should raise error when trying to process
        # (This would be caught in process() method)

