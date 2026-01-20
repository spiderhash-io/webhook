"""
Tests for input validation utilities.
"""

import pytest
from src.input_validator import InputValidator


# ============================================================================
# WEBHOOK ID VALIDATION TESTS
# ============================================================================


def test_valid_webhook_ids():
    """Test valid webhook ID formats."""
    valid_ids = [
        "webhook123",
        "my-webhook",
        "my_webhook",
        "webhook-123_test",
        "a",
        "ABC123",
    ]

    for webhook_id in valid_ids:
        is_valid, _ = InputValidator.validate_webhook_id(webhook_id)
        assert is_valid, f"Should accept valid ID: {webhook_id}"


def test_invalid_webhook_ids():
    """Test invalid webhook ID formats."""
    invalid_ids = [
        "webhook with spaces",
        "webhook@special",
        "webhook#123",
        "webhook/path",
        "webhook\\path",
        "../webhook",
        "webhook;drop",
        "x" * 101,  # Too long
    ]

    for webhook_id in invalid_ids:
        is_valid, _ = InputValidator.validate_webhook_id(webhook_id)
        assert not is_valid, f"Should reject invalid ID: {webhook_id}"


# ============================================================================
# PAYLOAD SIZE VALIDATION TESTS
# ============================================================================


def test_valid_payload_sizes():
    """Test valid payload sizes."""
    sizes = [0, 100, 1024, 1024 * 1024, 5 * 1024 * 1024]

    for size in sizes:
        payload = b"x" * size
        is_valid, _ = InputValidator.validate_payload_size(payload)
        assert is_valid, f"Should accept payload of size {size}"


def test_oversized_payload():
    """Test oversized payload rejection."""
    # 11MB payload (over 10MB limit)
    payload = b"x" * (11 * 1024 * 1024)
    is_valid, msg = InputValidator.validate_payload_size(payload)
    assert not is_valid
    assert "too large" in msg.lower()


# ============================================================================
# HEADER VALIDATION TESTS
# ============================================================================


def test_valid_headers():
    """Test valid header counts and sizes."""
    headers = {f"Header-{i}": f"Value-{i}" for i in range(50)}
    is_valid, _ = InputValidator.validate_headers(headers)
    assert is_valid


def test_too_many_headers():
    """Test rejection of too many headers."""
    headers = {f"Header-{i}": f"Value-{i}" for i in range(150)}
    is_valid, msg = InputValidator.validate_headers(headers)
    assert not is_valid
    assert "too many" in msg.lower()


def test_oversized_headers():
    """Test rejection of oversized headers."""
    headers = {"X-Large": "x" * 10000}
    is_valid, msg = InputValidator.validate_headers(headers)
    assert not is_valid
    assert "too large" in msg.lower()


# ============================================================================
# JSON DEPTH VALIDATION TESTS
# ============================================================================


def test_valid_json_depth():
    """Test valid JSON nesting depths."""
    # Create nested structure with 10 levels
    nested = {"level": 1}
    current = nested
    for i in range(2, 11):
        current["nested"] = {"level": i}
        current = current["nested"]

    is_valid, _ = InputValidator.validate_json_depth(nested)
    assert is_valid


def test_too_deep_json():
    """Test rejection of too deeply nested JSON."""
    # Create nested structure with 60 levels (over 50 limit)
    nested = {"level": 1}
    current = nested
    for i in range(2, 61):
        current["nested"] = {"level": i}
        current = current["nested"]

    is_valid, msg = InputValidator.validate_json_depth(nested)
    assert not is_valid
    assert "deeply nested" in msg.lower()


def test_json_depth_with_arrays():
    """Test JSON depth validation with arrays."""
    # Nested arrays
    nested = [[[[[[[[[[1]]]]]]]]]]  # 10 levels
    is_valid, _ = InputValidator.validate_json_depth(nested)
    assert is_valid


# ============================================================================
# STRING LENGTH VALIDATION TESTS
# ============================================================================


def test_valid_string_lengths():
    """Test valid string lengths."""
    data = {
        "short": "hello",
        "medium": "x" * 1000,
        "long": "x" * 100000,
    }
    is_valid, _ = InputValidator.validate_string_length(data)
    assert is_valid


def test_oversized_string():
    """Test rejection of oversized strings."""
    data = {"huge": "x" * (2 * 1024 * 1024)}  # 2MB string
    is_valid, msg = InputValidator.validate_string_length(data)
    assert not is_valid
    assert "too long" in msg.lower()


def test_string_length_in_nested_structure():
    """Test string length validation in nested structures."""
    data = {"level1": {"level2": {"huge_string": "x" * (2 * 1024 * 1024)}}}
    is_valid, msg = InputValidator.validate_string_length(data)
    assert not is_valid


# ============================================================================
# STRING SANITIZATION TESTS
# ============================================================================


def test_sanitize_html_characters():
    """Test HTML character sanitization."""
    test_cases = [
        ("<script>", "&lt;script&gt;"),
        ("Hello & World", "Hello &amp; World"),
        ('"quoted"', "&quot;quoted&quot;"),
        ("'single'", "&#x27;single&#x27;"),
        ("<div>Test</div>", "&lt;div&gt;Test&lt;/div&gt;"),
    ]

    for input_str, expected in test_cases:
        result = InputValidator.sanitize_string(input_str)
        assert result == expected, f"Failed to sanitize: {input_str}"


def test_sanitize_non_string():
    """Test sanitization of non-string values."""
    assert InputValidator.sanitize_string(123) == 123
    assert InputValidator.sanitize_string(None) is None
    assert InputValidator.sanitize_string(True) is True


# ============================================================================
# DANGEROUS PATTERN DETECTION TESTS
# ============================================================================


def test_detect_xss_patterns():
    """Test detection of XSS patterns."""
    dangerous_strings = [
        "<script>alert('XSS')</script>",
        "<SCRIPT>alert('XSS')</SCRIPT>",
        "javascript:alert('XSS')",
        "JAVASCRIPT:alert('XSS')",
        "<img onload=alert('XSS')>",
        "<div onclick=alert('XSS')>",
    ]

    for dangerous in dangerous_strings:
        is_safe, msg = InputValidator.check_dangerous_patterns(dangerous)
        assert not is_safe, f"Should detect dangerous pattern in: {dangerous}"


def test_safe_strings():
    """Test that safe strings pass pattern check."""
    safe_strings = [
        "Hello World",
        "This is a normal string",
        "Email: user@example.com",
        "Price: $100",
    ]

    for safe in safe_strings:
        is_safe, _ = InputValidator.check_dangerous_patterns(safe)
        assert is_safe, f"Should accept safe string: {safe}"


# ============================================================================
# COMPREHENSIVE VALIDATION TESTS
# ============================================================================


def test_validate_all_success():
    """Test successful comprehensive validation."""
    webhook_id = "test_webhook"
    payload_bytes = b'{"test": "data"}'
    headers = {"Content-Type": "application/json"}
    payload_obj = {"test": "data"}

    is_valid, msg = InputValidator.validate_all(
        webhook_id, payload_bytes, headers, payload_obj
    )
    assert is_valid
    assert "passed" in msg.lower()


def test_validate_all_invalid_webhook_id():
    """Test comprehensive validation with invalid webhook ID."""
    webhook_id = "invalid webhook id"
    payload_bytes = b'{"test": "data"}'
    headers = {"Content-Type": "application/json"}
    payload_obj = {"test": "data"}

    is_valid, msg = InputValidator.validate_all(
        webhook_id, payload_bytes, headers, payload_obj
    )
    assert not is_valid


def test_validate_all_oversized_payload():
    """Test comprehensive validation with oversized payload."""
    webhook_id = "test_webhook"
    payload_bytes = b"x" * (11 * 1024 * 1024)
    headers = {"Content-Type": "application/json"}
    payload_obj = {"test": "data"}

    is_valid, msg = InputValidator.validate_all(
        webhook_id, payload_bytes, headers, payload_obj
    )
    assert not is_valid
    assert "too large" in msg.lower()


def test_validate_all_too_deep_json():
    """Test comprehensive validation with too deep JSON."""
    webhook_id = "test_webhook"
    payload_bytes = b'{"test": "data"}'
    headers = {"Content-Type": "application/json"}

    # Create deeply nested structure
    nested = {"level": 1}
    current = nested
    for i in range(2, 61):
        current["nested"] = {"level": i}
        current = current["nested"]

    is_valid, msg = InputValidator.validate_all(
        webhook_id, payload_bytes, headers, nested
    )
    assert not is_valid
    assert "deeply nested" in msg.lower()


# ============================================================================
# EDGE CASE TESTS
# ============================================================================


def test_empty_payload():
    """Test validation of empty payload."""
    is_valid, _ = InputValidator.validate_payload_size(b"")
    assert is_valid


def test_empty_headers():
    """Test validation of empty headers."""
    is_valid, _ = InputValidator.validate_headers({})
    assert is_valid


def test_null_values_in_json():
    """Test validation with null values."""
    data = {
        "null_value": None,
        "empty_string": "",
        "zero": 0,
        "false": False,
    }
    is_valid, _ = InputValidator.validate_json_depth(data)
    assert is_valid


def test_unicode_in_strings():
    """Test validation with unicode characters."""
    data = {
        "emoji": "🎉🚀💻",
        "chinese": "你好世界",
        "arabic": "مرحبا بالعالم",
    }
    is_valid, _ = InputValidator.validate_string_length(data)
    assert is_valid
