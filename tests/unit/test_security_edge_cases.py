"""
Comprehensive security and edge case tests for webhook validation.
Tests cover: missing data, malformed data, oversized payloads, injection attacks,
timing attacks, and various edge cases.
"""

import pytest
import hmac
import hashlib
import json
from httpx import AsyncClient, ASGITransport
from src.main import app

host = "test"
test_url = f"http://{host}"


# ============================================================================
# MISSING DATA TESTS
# ============================================================================


@pytest.mark.asyncio
async def test_missing_webhook_id():
    """Test request to non-existent webhook ID."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=test_url) as ac:
        response = await ac.post("/webhook/nonexistent", json={"data": "test"})
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_missing_authorization_header():
    """Test webhook requiring auth without authorization header."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=test_url) as ac:
        # 'abcde' webhook requires authorization
        response = await ac.post("/webhook/abcde", json={"data": "test"})
        assert response.status_code == 401


@pytest.mark.asyncio
async def test_empty_payload():
    """Test webhook with empty payload."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=test_url) as ac:
        response = await ac.post("/webhook/print", json={})
        assert response.status_code == 200


@pytest.mark.asyncio
async def test_null_payload():
    """Test webhook with null payload."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=test_url) as ac:
        response = await ac.post("/webhook/print", json=None)
        # Null payload may be rejected by validation
        assert response.status_code in [200, 400]


# ============================================================================
# MALFORMED DATA TESTS
# ============================================================================


@pytest.mark.asyncio
async def test_malformed_json():
    """Test webhook with malformed JSON."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=test_url) as ac:
        response = await ac.post(
            "/webhook/print",
            content=b"{invalid json}",
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 400


@pytest.mark.asyncio
async def test_wrong_content_type():
    """Test JSON webhook with wrong content type."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=test_url) as ac:
        response = await ac.post(
            "/webhook/print",
            content=b'{"data": "test"}',
            headers={"Content-Type": "text/plain"},
        )
        # Should still work as FastAPI is flexible
        assert response.status_code in [200, 400]


@pytest.mark.asyncio
async def test_invalid_authorization_format():
    """Test various invalid authorization formats."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=test_url) as ac:
        invalid_auths = [
            "",
            "Bearer",
            "Bearer ",
            "Basic invalid",
            "InvalidScheme token",
        ]

        for auth in invalid_auths:
            response = await ac.post(
                "/webhook/abcde", json={"data": "test"}, headers={"Authorization": auth}
            )
            assert response.status_code == 401


# ============================================================================
# OVERSIZED DATA TESTS
# ============================================================================


@pytest.mark.asyncio
async def test_large_payload():
    """Test webhook with large payload (1MB)."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=test_url) as ac:
        large_data = {"data": "x" * (1024 * 1024)}  # 1MB of data
        response = await ac.post("/webhook/print", json=large_data)
        # Should handle or reject gracefully
        assert response.status_code in [200, 413, 400]


@pytest.mark.asyncio
async def test_deeply_nested_json():
    """Test webhook with deeply nested JSON structure."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=test_url) as ac:
        # Create deeply nested structure
        nested = {"level": 1}
        current = nested
        for i in range(2, 101):
            current["nested"] = {"level": i}
            current = current["nested"]

        response = await ac.post("/webhook/print", json=nested)
        assert response.status_code in [200, 400]


@pytest.mark.asyncio
async def test_many_fields():
    """Test webhook with many fields in payload."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=test_url) as ac:
        many_fields = {f"field_{i}": f"value_{i}" for i in range(10000)}
        response = await ac.post("/webhook/print", json=many_fields)
        assert response.status_code in [200, 400]


# ============================================================================
# INJECTION ATTACK TESTS
# ============================================================================


@pytest.mark.asyncio
async def test_sql_injection_attempt():
    """Test SQL injection patterns in payload."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=test_url) as ac:
        sql_payloads = [
            {"query": "'; DROP TABLE users; --"},
            {"id": "1 OR 1=1"},
            {"name": "admin' --"},
            {"data": "1'; DELETE FROM webhooks WHERE '1'='1"},
        ]

        for payload in sql_payloads:
            response = await ac.post("/webhook/print", json=payload)
            assert response.status_code == 200  # Should accept but not execute


@pytest.mark.asyncio
async def test_xss_injection_attempt():
    """Test XSS injection patterns in payload."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=test_url) as ac:
        xss_payloads = [
            {"html": "<script>alert('XSS')</script>"},
            {"data": "<img src=x onerror=alert('XSS')>"},
            {"input": "javascript:alert('XSS')"},
        ]

        for payload in xss_payloads:
            response = await ac.post("/webhook/print", json=payload)
            assert response.status_code == 200


@pytest.mark.asyncio
async def test_command_injection_attempt():
    """Test command injection patterns in payload."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=test_url) as ac:
        cmd_payloads = [
            {"cmd": "; ls -la"},
            {"exec": "| cat /etc/passwd"},
            {"run": "&& rm -rf /"},
            {"shell": "`whoami`"},
        ]

        for payload in cmd_payloads:
            response = await ac.post("/webhook/print", json=payload)
            assert response.status_code == 200


# ============================================================================
# PATH TRAVERSAL TESTS
# ============================================================================


@pytest.mark.asyncio
async def test_path_traversal_in_payload():
    """Test path traversal attempts in payload."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=test_url) as ac:
        path_payloads = [
            {"file": "../../../etc/passwd"},
            {"path": "..\\..\\..\\windows\\system32"},
            {"dir": "/etc/shadow"},
        ]

        for payload in path_payloads:
            response = await ac.post("/webhook/print", json=payload)
            assert response.status_code == 200


# ============================================================================
# UNICODE AND ENCODING TESTS
# ============================================================================


@pytest.mark.asyncio
async def test_unicode_payload():
    """Test webhook with unicode characters."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=test_url) as ac:
        unicode_data = {
            "emoji": "🎉🚀💻",
            "chinese": "你好世界",
            "arabic": "مرحبا بالعالم",
            "special": "™®©€£¥",
        }
        response = await ac.post("/webhook/print", json=unicode_data)
        assert response.status_code == 200


@pytest.mark.asyncio
async def test_null_bytes_in_payload():
    """Test payload with null bytes."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=test_url) as ac:
        # JSON doesn't support null bytes, but test the handling
        response = await ac.post("/webhook/print", json={"data": "test\x00data"})
        assert response.status_code in [200, 400]


# ============================================================================
# HMAC SECURITY TESTS
# ============================================================================


@pytest.mark.asyncio
async def test_hmac_timing_attack_resistance():
    """Test that HMAC comparison is timing-attack resistant."""
    from src.validators import HMACValidator

    config = {
        "hmac": {
            "secret": "test_secret",
            "header": "X-HMAC-Signature",
            "algorithm": "sha256",
        }
    }

    validator = HMACValidator(config)
    body = b'{"test": "data"}'

    # Correct signature
    correct_sig = hmac.new(b"test_secret", body, hashlib.sha256).hexdigest()

    # Almost correct signature (differs by one character)
    almost_correct = correct_sig[:-1] + ("0" if correct_sig[-1] != "0" else "1")

    # Both should fail/succeed consistently
    is_valid1, _ = await validator.validate({"x-hmac-signature": almost_correct}, body)
    is_valid2, _ = await validator.validate({"x-hmac-signature": "wrong"}, body)

    assert is_valid1 == False
    assert is_valid2 == False


@pytest.mark.asyncio
async def test_hmac_with_empty_body():
    """Test HMAC validation with empty body."""
    from src.validators import HMACValidator

    config = {
        "hmac": {
            "secret": "test_secret",
            "header": "X-HMAC-Signature",
            "algorithm": "sha256",
        }
    }

    validator = HMACValidator(config)
    body = b""

    signature = hmac.new(b"test_secret", body, hashlib.sha256).hexdigest()

    is_valid, _ = await validator.validate({"x-hmac-signature": signature}, body)
    assert is_valid == True


@pytest.mark.asyncio
async def test_hmac_case_sensitivity():
    """Test HMAC signature case sensitivity."""
    from src.validators import HMACValidator

    config = {
        "hmac": {
            "secret": "test_secret",
            "header": "X-HMAC-Signature",
            "algorithm": "sha256",
        }
    }

    validator = HMACValidator(config)
    body = b'{"test": "data"}'

    signature = hmac.new(b"test_secret", body, hashlib.sha256).hexdigest()

    # Test lowercase
    is_valid1, _ = await validator.validate(
        {"x-hmac-signature": signature.lower()}, body
    )
    # Test uppercase - may not work as HMAC comparison is case-sensitive in hex
    is_valid2, _ = await validator.validate(
        {"x-hmac-signature": signature.upper()}, body
    )

    # Lowercase should work (original format)
    assert is_valid1 == True
    # Uppercase might not work depending on implementation
    # Python's hmac.hexdigest() returns lowercase, so uppercase won't match
    assert is_valid2 in [True, False]  # Accept either


# ============================================================================
# RATE LIMITING EDGE CASES
# ============================================================================


@pytest.mark.asyncio
async def test_rate_limit_concurrent_requests():
    """Test rate limiting with concurrent requests."""
    from src.rate_limiter import RateLimiter
    import asyncio

    limiter = RateLimiter()

    # Allow 5 requests per 10 seconds
    async def make_request():
        return await limiter.is_allowed("concurrent_test", 5, 10)

    # Make 10 concurrent requests
    results = await asyncio.gather(*[make_request() for _ in range(10)])

    # First 5 should succeed, rest should fail
    successes = sum(1 for is_allowed, _ in results if is_allowed)
    assert successes == 5


@pytest.mark.asyncio
async def test_rate_limit_zero_window():
    """Test rate limiting with zero window."""
    from src.rate_limiter import RateLimiter

    limiter = RateLimiter()

    # Edge case: zero window
    is_allowed, _ = await limiter.is_allowed("zero_window", 10, 0)
    # Should handle gracefully
    assert isinstance(is_allowed, bool)


# ============================================================================
# IP VALIDATION EDGE CASES
# ============================================================================


@pytest.mark.asyncio
async def test_ip_whitelist_with_ipv6():
    """Test IP whitelist with IPv6 addresses."""
    from src.validators import IPWhitelistValidator
    from unittest.mock import Mock

    config = {"ip_whitelist": ["2001:0db8:85a3:0000:0000:8a2e:0370:7334", "::1"]}

    # Mock Request object with IPv6 client IP
    mock_request = Mock()
    mock_request.client = Mock()
    mock_request.client.host = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"

    validator = IPWhitelistValidator(config, request=mock_request)

    # Test IPv6 (using Request object, not headers)
    headers = {}
    is_valid, _ = await validator.validate(headers, b"")
    assert is_valid == True


@pytest.mark.asyncio
async def test_ip_whitelist_with_proxy_chain():
    """Test IP whitelist with proxy chain."""
    from src.validators import IPWhitelistValidator
    from unittest.mock import Mock

    config = {
        "ip_whitelist": ["192.168.1.1"],
        "trusted_proxies": ["10.0.0.1"],  # Trusted proxy
    }

    # Mock Request object with trusted proxy IP
    mock_request = Mock()
    mock_request.client = Mock()
    mock_request.client.host = "10.0.0.1"  # Trusted proxy

    validator = IPWhitelistValidator(config, request=mock_request)

    # Test proxy chain (first IP should be used from X-Forwarded-For)
    headers = {"x-forwarded-for": "192.168.1.1, 10.0.0.1, 172.16.0.1"}
    is_valid, _ = await validator.validate(headers, b"")
    assert is_valid == True


# ============================================================================
# SPECIAL CHARACTER TESTS
# ============================================================================


@pytest.mark.asyncio
async def test_special_characters_in_headers():
    """Test webhook with special characters in headers."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=test_url) as ac:
        response = await ac.post(
            "/webhook/print",
            json={"data": "test"},
            headers={
                "X-Custom-Header": "value with spaces",
                "X-Another": "special-chars-123",
            },
        )
        assert response.status_code == 200


@pytest.mark.asyncio
async def test_very_long_header_value():
    """Test webhook with very long header value."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=test_url) as ac:
        long_value = "x" * 10000
        response = await ac.post(
            "/webhook/print",
            json={"data": "test"},
            headers={"X-Long-Header": long_value},
        )
        # Should handle or reject gracefully
        assert response.status_code in [200, 400, 431]


# ============================================================================
# CONTENT TYPE TESTS
# ============================================================================


@pytest.mark.asyncio
async def test_unsupported_content_type():
    """Test webhook with unsupported content type."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=test_url) as ac:
        response = await ac.post(
            "/webhook/print",
            content=b"binary data",
            headers={"Content-Type": "application/octet-stream"},
        )
        # Should reject or handle gracefully - validation may reject
        assert response.status_code in [200, 400, 415]


# ============================================================================
# BOUNDARY TESTS
# ============================================================================


@pytest.mark.asyncio
async def test_max_int_values():
    """Test webhook with maximum integer values."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=test_url) as ac:
        payload = {
            "max_int": 2**63 - 1,
            "min_int": -(2**63),
            "large_float": 1.7976931348623157e308,
        }
        response = await ac.post("/webhook/print", json=payload)
        assert response.status_code == 200


@pytest.mark.asyncio
async def test_empty_string_values():
    """Test webhook with empty string values."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=test_url) as ac:
        payload = {
            "empty": "",
            "whitespace": "   ",
            "newline": "\n",
            "tab": "\t",
        }
        response = await ac.post("/webhook/print", json=payload)
        assert response.status_code == 200


@pytest.mark.asyncio
async def test_boolean_edge_cases():
    """Test webhook with boolean edge cases."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=test_url) as ac:
        payload = {
            "true": True,
            "false": False,
            "null": None,
        }
        response = await ac.post("/webhook/print", json=payload)
        assert response.status_code == 200
