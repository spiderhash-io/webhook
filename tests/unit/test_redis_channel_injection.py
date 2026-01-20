"""
Security tests for Redis publish module channel name injection prevention.
Tests channel name validation to prevent injection attacks.
"""

import pytest
from src.modules.redis_publish import RedisPublishModule


class TestRedisChannelInjection:
    """Test suite for Redis channel name injection prevention."""

    def test_valid_channel_names(self):
        """Test that valid channel names are accepted."""
        valid_names = [
            "webhook_events",
            "webhook_events_2024",
            "webhook-events",
            "webhook.events",
            "webhook123",
            "a",
            "A" * 100,  # Long but valid
            "webhook_events.test",
            "webhook-events_test",
        ]

        for channel_name in valid_names:
            config = {
                "module": "redis_publish",
                "redis": {
                    "host": "8.8.8.8",  # Use public IP instead of localhost (blocked by SSRF protection)
                    "port": 6379,
                    "channel": channel_name,
                },
            }
            module = RedisPublishModule(config)
            assert module._validated_channel == channel_name

    def test_injection_attempts_rejected(self):
        """Test that injection attempts in channel names are rejected."""
        injection_attempts = [
            "webhook_events; FLUSHALL",
            "webhook_events | CONFIG GET *",
            "webhook_events && DEL *",
            "webhook_events\nPUBLISH",
            "webhook_events\rPUBLISH",
            "webhook_events\x00PUBLISH",
            "webhook_events`eval`",
            "webhook_events$(command)",
        ]

        for malicious_name in injection_attempts:
            config = {
                "module": "redis_publish",
                "redis": {
                    "host": "8.8.8.8",  # Use public IP instead of localhost (blocked by SSRF protection)
                    "port": 6379,
                    "channel": malicious_name,
                },
            }
            with pytest.raises(ValueError) as exc_info:
                RedisPublishModule(config)
            error_msg = str(exc_info.value).lower()
            assert any(
                keyword in error_msg
                for keyword in ["invalid", "forbidden", "dangerous", "not allowed"]
            ), f"Failed to reject injection attempt: {malicious_name}"

    def test_redis_keywords_rejected(self):
        """Test that Redis command keywords in channel names are rejected."""
        redis_keywords = [
            "PUBLISH",
            "SUBSCRIBE",
            "PSUBSCRIBE",
            "KEYS",
            "GET",
            "SET",
            "DEL",
            "FLUSHALL",
            "CONFIG",
            "EVAL",
            "SCRIPT",
        ]

        for keyword in redis_keywords:
            # Test as exact match
            config = {
                "module": "redis_publish",
                "redis": {
                    "host": "8.8.8.8",  # Use public IP instead of localhost (blocked by SSRF protection)
                    "port": 6379,
                    "channel": keyword.lower(),
                },
            }
            with pytest.raises(ValueError) as exc_info:
                RedisPublishModule(config)
            assert (
                "forbidden" in str(exc_info.value).lower()
                or "keyword" in str(exc_info.value).lower()
            )

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
        ]

        for pattern in dangerous_patterns:
            config = {
                "module": "redis_publish",
                "redis": {
                    "host": "8.8.8.8",  # Use public IP instead of localhost (blocked by SSRF protection)
                    "port": 6379,
                    "channel": pattern,
                },
            }
            with pytest.raises(ValueError) as exc_info:
                RedisPublishModule(config)
            error_msg = str(exc_info.value).lower()
            assert any(
                keyword in error_msg
                for keyword in ["invalid", "forbidden", "dangerous", "not allowed"]
            ), f"Failed to reject dangerous pattern: {pattern}"

    def test_special_characters_rejected(self):
        """Test that special characters are rejected."""
        special_chars = [
            "webhook events",  # Space
            "webhook/events",  # Slash
            "webhook\\events",  # Backslash
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
                "module": "redis_publish",
                "redis": {
                    "host": "8.8.8.8",  # Use public IP instead of localhost (blocked by SSRF protection)
                    "port": 6379,
                    "channel": name,
                },
            }
            with pytest.raises(ValueError) as exc_info:
                RedisPublishModule(config)
            assert "Invalid channel name" in str(exc_info.value)

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
                "module": "redis_publish",
                "redis": {
                    "host": "8.8.8.8",  # Use public IP instead of localhost (blocked by SSRF protection)
                    "port": 6379,
                    "channel": name,
                },
            }
            with pytest.raises(ValueError) as exc_info:
                RedisPublishModule(config)
            assert "Invalid channel name" in str(exc_info.value)

    def test_empty_channel_name_rejected(self):
        """Test that empty channel names are rejected."""
        empty_names = ["", "   ", None]

        for name in empty_names:
            config = {
                "module": "redis_publish",
                "redis": {
                    "host": "8.8.8.8",  # Use public IP instead of localhost (blocked by SSRF protection)
                    "port": 6379,
                    "channel": name,
                },
            }
            with pytest.raises(ValueError) as exc_info:
                RedisPublishModule(config)
            assert (
                "empty" in str(exc_info.value).lower()
                or "non-empty string" in str(exc_info.value).lower()
            )

    def test_channel_name_length_limit(self):
        """Test that very long channel names are rejected."""
        # Create a very long but valid channel name
        long_name = "a" * 300  # Exceeds 255 character limit

        config = {
            "module": "redis_publish",
            "redis": {
                "host": "8.8.8.8",  # Use public IP instead of localhost (blocked by SSRF protection)
                "port": 6379,
                "channel": long_name,
            },
        }
        with pytest.raises(ValueError) as exc_info:
            RedisPublishModule(config)
        assert "too long" in str(exc_info.value).lower()

    def test_channel_name_whitespace_handling(self):
        """Test that whitespace is properly handled."""
        # Whitespace should be stripped
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "8.8.8.8",  # Use public IP instead of localhost (blocked by SSRF protection)
                "port": 6379,
                "channel": "  webhook_events  ",
            },
        }
        module = RedisPublishModule(config)
        # Whitespace is stripped during validation in __init__
        assert module._validated_channel == "webhook_events"

        # But whitespace-only should be rejected
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "8.8.8.8",  # Use public IP instead of localhost (blocked by SSRF protection)
                "port": 6379,
                "channel": "   ",
            },
        }
        with pytest.raises(ValueError):
            RedisPublishModule(config)

    def test_channel_name_case_sensitivity(self):
        """Test that channel names are case-sensitive (preserved)."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "8.8.8.8",  # Use public IP instead of localhost (blocked by SSRF protection)
                "port": 6379,
                "channel": "WebhookEvents",
            },
        }
        module = RedisPublishModule(config)
        assert module._validated_channel == "WebhookEvents"

    def test_default_channel_name(self):
        """Test that default channel name is used when not specified."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "8.8.8.8",  # Use public IP instead of localhost (blocked by SSRF protection)
                "port": 6379,
            },
        }
        module = RedisPublishModule(config)
        # Default channel name is validated during __init__
        assert module._validated_channel == "webhook_events"

    def test_channel_name_with_numbers(self):
        """Test that channel names with numbers are accepted."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "8.8.8.8",  # Use public IP instead of localhost (blocked by SSRF protection)
                "port": 6379,
                "channel": "webhook_events_2024_01",
            },
        }
        module = RedisPublishModule(config)
        assert module._validated_channel == "webhook_events_2024_01"

    def test_channel_name_underscore_hyphen_dot(self):
        """Test edge cases with underscores, hyphens, and dots."""
        valid_names = [
            "webhook__events",  # Double underscore
            "webhook--events",  # Double hyphen (should be rejected due to dangerous pattern)
            "webhook..events",  # Double dot (should be rejected due to dangerous pattern)
            "webhook.events.test",  # Multiple dots
            "webhook-events-test",  # Multiple hyphens
            "webhook_events_test",  # Multiple underscores
        ]

        for name in valid_names:
            config = {
                "module": "redis_publish",
                "redis": {
                    "host": "8.8.8.8",  # Use public IP instead of localhost (blocked by SSRF protection)
                    "port": 6379,
                    "channel": name,
                },
            }
            # Double hyphen and double dot should be rejected
            if "--" in name or ".." in name:
                with pytest.raises(ValueError):
                    RedisPublishModule(config)
            else:
                module = RedisPublishModule(config)
                assert module._validated_channel == name

    def test_channel_name_starts_with_number(self):
        """Test that channel names starting with numbers are accepted."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "8.8.8.8",  # Use public IP instead of localhost (blocked by SSRF protection)
                "port": 6379,
                "channel": "2024_webhook_events",
            },
        }
        module = RedisPublishModule(config)
        assert module._validated_channel == "2024_webhook_events"

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
                "module": "redis_publish",
                "redis": {
                    "host": "8.8.8.8",  # Use public IP instead of localhost (blocked by SSRF protection)
                    "port": 6379,
                    "channel": name,
                },
            }
            with pytest.raises(ValueError) as exc_info:
                RedisPublishModule(config)
            error_msg = str(exc_info.value).lower()
            assert any(
                keyword in error_msg
                for keyword in ["invalid", "forbidden", "control", "not allowed"]
            )

    def test_redis_command_injection_patterns(self):
        """Test various Redis command injection patterns."""
        injection_patterns = [
            ("webhook; FLUSHALL", "command separator"),
            ("webhook | CONFIG GET *", "pipe to command"),
            ("webhook && DEL *", "logical AND"),
            ("webhook || KEYS *", "logical OR"),
            ("webhook`eval`", "command substitution"),
            ("webhook$(command)", "command expansion"),
            ("webhook\nPUBLISH", "newline injection"),
            ("webhook\rPUBLISH", "carriage return injection"),
        ]

        for pattern, description in injection_patterns:
            config = {
                "module": "redis_publish",
                "redis": {
                    "host": "8.8.8.8",  # Use public IP instead of localhost (blocked by SSRF protection)
                    "port": 6379,
                    "channel": pattern,
                },
            }
            with pytest.raises(ValueError) as exc_info:
                RedisPublishModule(config)
            error_msg = str(exc_info.value).lower()
            assert any(
                keyword in error_msg
                for keyword in [
                    "invalid",
                    "forbidden",
                    "dangerous",
                    "not allowed",
                    "control",
                ]
            ), f"Failed to reject injection pattern: {description}"
