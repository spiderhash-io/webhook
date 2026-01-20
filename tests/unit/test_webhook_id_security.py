"""
Security tests for webhook ID validation.
Tests that webhook IDs are properly validated to prevent DoS and reserved name conflicts.
"""

import pytest
from src.input_validator import InputValidator


class TestWebhookIDSecurity:
    """Test suite for webhook ID validation security."""

    def test_reserved_names_blocked(self):
        """Test that reserved names are blocked."""
        reserved_names = [
            "stats",
            "health",
            "docs",
            "api",
            "admin",
            "root",
            "system",
            "internal",
        ]

        for name in reserved_names:
            # Test lowercase
            is_valid, msg = InputValidator.validate_webhook_id(name)
            assert not is_valid, f"Should reject reserved name: {name}"
            assert "reserved" in msg.lower()

            # Test uppercase
            is_valid, msg = InputValidator.validate_webhook_id(name.upper())
            assert (
                not is_valid
            ), f"Should reject reserved name (uppercase): {name.upper()}"

            # Test mixed case
            is_valid, msg = InputValidator.validate_webhook_id(name.capitalize())
            assert (
                not is_valid
            ), f"Should reject reserved name (mixed case): {name.capitalize()}"

    def test_reserved_prefixes_blocked(self):
        """Test that reserved prefixes are blocked."""
        reserved_prefixes = [
            ("_", "prefix"),
            ("__", "prefix"),
            ("internal_", "prefix"),
            ("system_", "prefix"),
            ("admin_", "prefix"),
        ]

        for prefix, expected_msg in reserved_prefixes:
            test_id = f"{prefix}webhook"
            is_valid, msg = InputValidator.validate_webhook_id(test_id)
            assert not is_valid, f"Should reject ID with reserved prefix: {test_id}"
            # Some prefixes might be caught by "must start with alphanumeric" check
            assert (
                expected_msg in msg.lower() or "start with alphanumeric" in msg.lower()
            )

    def test_reserved_suffixes_blocked(self):
        """Test that reserved suffixes are blocked."""
        reserved_suffixes = [
            "_internal",
            "_system",
            "_admin",
        ]

        for suffix in reserved_suffixes:
            test_id = f"webhook{suffix}"
            is_valid, msg = InputValidator.validate_webhook_id(test_id)
            assert not is_valid, f"Should reject ID with reserved suffix: {test_id}"
            assert "suffix" in msg.lower()

        # _test and _debug are allowed (common in development)
        allowed_suffixes = ["_test", "_debug"]
        for suffix in allowed_suffixes:
            test_id = f"webhook{suffix}"
            is_valid, msg = InputValidator.validate_webhook_id(test_id)
            assert is_valid, f"Should allow ID with non-reserved suffix: {test_id}"

    def test_max_length_enforced(self):
        """Test that maximum length is enforced to prevent DoS."""
        # Test exactly at limit (64 chars)
        valid_id = "a" * 64
        is_valid, msg = InputValidator.validate_webhook_id(valid_id)
        assert is_valid, f"Should accept ID at limit: {len(valid_id)} chars"

        # Test over limit (65 chars)
        invalid_id = "a" * 65
        is_valid, msg = InputValidator.validate_webhook_id(invalid_id)
        assert not is_valid, f"Should reject ID over limit: {len(invalid_id)} chars"
        assert "too long" in msg.lower()

    def test_extremely_long_ids_blocked(self):
        """Test that extremely long IDs are blocked (DoS prevention)."""
        long_ids = [
            "a" * 100,
            "a" * 1000,
            "a" * 10000,
        ]

        for long_id in long_ids:
            is_valid, msg = InputValidator.validate_webhook_id(long_id)
            assert (
                not is_valid
            ), f"Should reject extremely long ID: {len(long_id)} chars"
            assert "too long" in msg.lower()

    def test_empty_id_rejected(self):
        """Test that empty IDs are rejected."""
        empty_ids = [
            "",
            "   ",
            "\t",
            "\n",
        ]

        for empty_id in empty_ids:
            is_valid, msg = InputValidator.validate_webhook_id(empty_id)
            assert not is_valid, f"Should reject empty/whitespace ID: {repr(empty_id)}"
            assert "empty" in msg.lower() or "whitespace" in msg.lower()

    def test_must_start_with_alphanumeric(self):
        """Test that IDs must start with alphanumeric character."""
        invalid_start_ids = [
            "_webhook",
            "-webhook",
            "123webhook",  # Starting with number is OK
        ]

        # Only underscore and hyphen at start should be rejected
        for invalid_id in ["_webhook", "-webhook"]:
            is_valid, msg = InputValidator.validate_webhook_id(invalid_id)
            assert (
                not is_valid
            ), f"Should reject ID starting with special char: {invalid_id}"

        # Starting with number should be OK
        is_valid, msg = InputValidator.validate_webhook_id("123webhook")
        assert is_valid, "Should accept ID starting with number"

    def test_consecutive_special_chars_blocked(self):
        """Test that consecutive underscores or hyphens are blocked."""
        invalid_ids = [
            "webhook--id",  # Consecutive hyphens
            "webhook__id",  # Consecutive underscores
            "webhook---id",  # Multiple consecutive hyphens
            "webhook___id",  # Multiple consecutive underscores
        ]

        for invalid_id in invalid_ids:
            is_valid, msg = InputValidator.validate_webhook_id(invalid_id)
            assert (
                not is_valid
            ), f"Should reject ID with consecutive special chars: {invalid_id}"
            assert "consecutive" in msg.lower()

        # Mixed special chars (hyphen-underscore) should be allowed
        valid_mixed = "webhook-_id"
        is_valid, msg = InputValidator.validate_webhook_id(valid_mixed)
        assert is_valid, f"Should allow mixed special chars: {valid_mixed}"

    def test_only_special_chars_blocked(self):
        """Test that IDs consisting only of special characters are blocked."""
        invalid_ids = [
            "___",
            "---",
            "_-_",
            "-_-",
        ]

        for invalid_id in invalid_ids:
            is_valid, msg = InputValidator.validate_webhook_id(invalid_id)
            assert (
                not is_valid
            ), f"Should reject ID with only special chars: {invalid_id}"

    def test_valid_ids_accepted(self):
        """Test that valid IDs are accepted."""
        valid_ids = [
            "webhook123",
            "my-webhook",
            "my_webhook",
            "webhook-123_test",
            "a",
            "ABC123",
            "webhook123test",
            "test-webhook-123",
        ]

        for valid_id in valid_ids:
            is_valid, msg = InputValidator.validate_webhook_id(valid_id)
            assert is_valid, f"Should accept valid ID: {valid_id}"

    def test_case_insensitive_reserved_names(self):
        """Test that reserved name checking is case-insensitive."""
        reserved_name = "stats"
        variations = [
            "STATS",
            "Stats",
            "StAtS",
            "sTaTs",
        ]

        for variation in variations:
            is_valid, msg = InputValidator.validate_webhook_id(variation)
            assert (
                not is_valid
            ), f"Should reject reserved name (case variation): {variation}"

    def test_reserved_name_not_in_substring(self):
        """Test that reserved names in substrings are allowed."""
        # "stats" is reserved, but "mystats" should be allowed
        is_valid, msg = InputValidator.validate_webhook_id("mystats")
        assert is_valid, "Should allow reserved name as substring"

        # "admin" is reserved, but "adminuser" should be allowed
        is_valid, msg = InputValidator.validate_webhook_id("adminuser")
        assert is_valid, "Should allow reserved name as substring"

    def test_none_rejected(self):
        """Test that None is rejected."""
        is_valid, msg = InputValidator.validate_webhook_id(None)
        assert not is_valid, "Should reject None"
        assert "non-empty string" in msg.lower()

    def test_non_string_rejected(self):
        """Test that non-string types are rejected."""
        invalid_types = [
            123,
            [],
            {},
            True,
        ]

        for invalid_type in invalid_types:
            is_valid, msg = InputValidator.validate_webhook_id(invalid_type)
            assert not is_valid, f"Should reject non-string type: {type(invalid_type)}"
            assert "non-empty string" in msg.lower()
