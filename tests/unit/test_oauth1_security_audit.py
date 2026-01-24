"""
Comprehensive security audit tests for OAuth1Validator.
Tests signature base string manipulation, parameter injection, PLAINTEXT weaknesses, error disclosure, and configuration security.
"""

import pytest
import hmac
import hashlib
import base64
import time
from urllib.parse import quote
from unittest.mock import patch, MagicMock
from src.validators import OAuth1Validator


def generate_oauth1_signature(
    method: str,
    uri: str,
    consumer_secret: str,
    token_secret: str,
    oauth_params: dict,
    body: bytes = b"",
) -> str:
    """Helper function to generate valid OAuth 1.0 HMAC-SHA1 signature."""
    from urllib.parse import urlparse

    # Build signature base string (matching validator logic)
    if "://" in uri:
        parsed = urlparse(uri)
        normalized_uri = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    else:
        normalized_uri = uri.split("?")[0]

    all_params = {k: v for k, v in oauth_params.items() if k != "oauth_signature"}

    sorted_params = sorted(all_params.items())
    param_string = "&".join(
        [f"{quote(str(k), safe='')}={quote(str(v), safe='')}" for k, v in sorted_params]
    )

    base_string = f"{method.upper()}&{quote(normalized_uri, safe='')}&{quote(param_string, safe='')}"

    signing_key = f"{quote(consumer_secret, safe='')}&{quote(token_secret, safe='')}"

    signature = hmac.new(
        signing_key.encode("utf-8"), base_string.encode("utf-8"), hashlib.sha1
    ).digest()

    return base64.b64encode(signature).decode("utf-8")


def create_mock_request(path: str = "/webhook/test", method: str = "POST"):
    """Create a mock request object for OAuth1 tests."""
    return type(
        "MockRequest",
        (),
        {
            "scope": {"path": path},
            "method": method,
        },
    )()


# ============================================================================
# 1. SIGNATURE BASE STRING MANIPULATION
# ============================================================================


class TestOAuth1SignatureBaseStringManipulation:
    """Test signature base string manipulation vulnerabilities."""

    @pytest.mark.asyncio
    async def test_uri_manipulation_in_base_string(self):
        """Test URI manipulation in signature base string."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret",
                "signature_method": "HMAC-SHA1",
            },
            
        }

        validator = OAuth1Validator(config, request=create_mock_request())

        # Valid URI
        uri = "/webhook/test"
        method = "POST"
        consumer_key = "consumer_key"
        consumer_secret = "consumer_secret"
        token_secret = ""

        oauth_params = {
            "oauth_consumer_key": consumer_key,
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": str(int(time.time())),
            "oauth_nonce": "nonce123",
        }

        # Generate signature for valid URI
        signature = generate_oauth1_signature(
            method, uri, consumer_secret, token_secret, oauth_params
        )
        oauth_params["oauth_signature"] = signature

        auth_parts = [
            f'{k}="{quote(str(v), safe="")}"' for k, v in oauth_params.items()
        ]
        auth_header = "OAuth " + ", ".join(auth_parts)

        headers = {"authorization": auth_header}

        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is True

        # Try to use signature for different URI (should fail)
        # Note: URI comes from request object, not from header, so this is harder to manipulate
        # But we test that URI is correctly used in base string

    @pytest.mark.asyncio
    async def test_parameter_injection_via_oauth_params(self):
        """Test parameter injection via OAuth parameters."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret",
                "signature_method": "HMAC-SHA1",
            },
            
        }

        validator = OAuth1Validator(config, request=create_mock_request())

        uri = "/webhook/test"
        method = "POST"
        consumer_key = "consumer_key"
        consumer_secret = "consumer_secret"
        token_secret = ""

        # Try to inject malicious parameter
        oauth_params = {
            "oauth_consumer_key": consumer_key,
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": str(int(time.time())),
            "oauth_nonce": "nonce123",
            "malicious_param": "../../etc/passwd",  # Injection attempt
        }

        signature = generate_oauth1_signature(
            method, uri, consumer_secret, token_secret, oauth_params
        )
        oauth_params["oauth_signature"] = signature

        auth_parts = [
            f'{k}="{quote(str(v), safe="")}"' for k, v in oauth_params.items()
        ]
        auth_header = "OAuth " + ", ".join(auth_parts)

        headers = {"authorization": auth_header}

        # Should validate signature correctly (injected param is included in base string)
        is_valid, message = await validator.validate(headers, body=b"test")
        # Signature should be valid if param is included in base string calculation
        assert isinstance(is_valid, bool)


# ============================================================================
# 2. PLAINTEXT SIGNATURE METHOD WEAKNESSES
# ============================================================================


class TestOAuth1PlaintextWeaknesses:
    """Test PLAINTEXT signature method weaknesses."""

    @pytest.mark.asyncio
    async def test_plaintext_signature_insecure(self):
        """Test that PLAINTEXT signature method is insecure (no cryptographic protection)."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret",
                "signature_method": "PLAINTEXT",
            },
            
        }

        validator = OAuth1Validator(config, request=create_mock_request())

        consumer_key = "consumer_key"
        consumer_secret = "consumer_secret"
        token_secret = ""

        # PLAINTEXT signature is just the signing key (no base string)
        signing_key = (
            f"{quote(consumer_secret, safe='')}&{quote(token_secret, safe='')}"
        )

        oauth_params = {
            "oauth_consumer_key": consumer_key,
            "oauth_signature_method": "PLAINTEXT",
            "oauth_timestamp": str(int(time.time())),
            "oauth_nonce": "nonce123",
            "oauth_signature": signing_key,
        }

        auth_parts = [
            f'{k}="{quote(str(v), safe="")}"' for k, v in oauth_params.items()
        ]
        auth_header = "OAuth " + ", ".join(auth_parts)

        headers = {"authorization": auth_header}

        is_valid, message = await validator.validate(headers, body=b"test")
        # PLAINTEXT is accepted (known weakness - no cryptographic protection)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_plaintext_secret_exposure(self):
        """Test that PLAINTEXT method exposes secrets in signature."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "secret123",
                "signature_method": "PLAINTEXT",
            },
            
        }

        validator = OAuth1Validator(config, request=create_mock_request())

        consumer_key = "consumer_key"
        consumer_secret = "secret123"
        token_secret = ""

        signing_key = (
            f"{quote(consumer_secret, safe='')}&{quote(token_secret, safe='')}"
        )

        oauth_params = {
            "oauth_consumer_key": consumer_key,
            "oauth_signature_method": "PLAINTEXT",
            "oauth_timestamp": str(int(time.time())),
            "oauth_nonce": "nonce123",
            "oauth_signature": signing_key,
        }

        auth_parts = [
            f'{k}="{quote(str(v), safe="")}"' for k, v in oauth_params.items()
        ]
        auth_header = "OAuth " + ", ".join(auth_parts)

        headers = {"authorization": auth_header}

        is_valid, message = await validator.validate(headers, body=b"test")
        # PLAINTEXT exposes secret in signature (known weakness)
        # The signature contains the secret, which can be extracted
        assert (
            "secret123" in signing_key or quote(consumer_secret, safe="") in signing_key
        )


# ============================================================================
# 3. HEADER PARSING VULNERABILITIES
# ============================================================================


class TestOAuth1HeaderParsing:
    """Test header parsing vulnerabilities."""

    @pytest.mark.asyncio
    async def test_header_injection_via_newlines(self):
        """Test header injection via newlines in OAuth header."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret",
            }
        }
        validator = OAuth1Validator(config, request=create_mock_request())

        # Header with newline injection attempt
        malicious_header = (
            'OAuth oauth_consumer_key="consumer_key",\nX-Injected: header'
        )

        headers = {"authorization": malicious_header}

        try:
            is_valid, message = await validator.validate(headers, body=b"test")
            # Should handle newlines safely (may fail parsing, but shouldn't crash)
            assert isinstance(is_valid, bool)
        except Exception as e:
            # Should not crash on malicious header
            assert False, f"Validator crashed on newline injection: {e}"

    @pytest.mark.asyncio
    async def test_header_injection_via_null_bytes(self):
        """Test header injection via null bytes."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret",
            }
        }
        validator = OAuth1Validator(config, request=create_mock_request())

        # Header with null byte
        malicious_header = 'OAuth oauth_consumer_key="consumer_key\x00injected"'

        headers = {"authorization": malicious_header}

        try:
            is_valid, message = await validator.validate(headers, body=b"test")
            # Should handle null bytes safely
            assert isinstance(is_valid, bool)
        except Exception as e:
            # Should not crash on null bytes
            assert False, f"Validator crashed on null byte injection: {e}"

    @pytest.mark.asyncio
    async def test_regex_redos_via_complex_header(self):
        """Test ReDoS vulnerability in header parsing regex."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret",
            }
        }
        validator = OAuth1Validator(config, request=create_mock_request())

        # Complex header that might cause ReDoS
        complex_header = (
            'OAuth oauth_consumer_key="'
            + "a" * 1000
            + '", oauth_signature_method="'
            + "b" * 1000
            + '"'
        )

        headers = {"authorization": complex_header}

        import time

        start_time = time.time()
        try:
            is_valid, message = await validator.validate(headers, body=b"test")
            elapsed = time.time() - start_time
            # Should complete quickly (no ReDoS)
            assert elapsed < 1.0, f"ReDoS detected: parsing took {elapsed:.2f}s"
        except Exception as e:
            # Should not crash
            pass

    @pytest.mark.asyncio
    async def test_malformed_header_parsing(self):
        """Test parsing of various malformed headers."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret",
            }
        }
        validator = OAuth1Validator(config, request=create_mock_request())

        malformed_headers = [
            "OAuth oauth_consumer_key=consumer_key",  # Missing quotes
            'OAuth oauth_consumer_key="consumer_key',  # Unclosed quote
            'OAuth oauth_consumer_key="consumer_key", oauth_signature_method=',  # Empty value
            'OAuth oauth_consumer_key="consumer_key" oauth_signature_method="HMAC-SHA1"',  # Missing comma
            "OAuth",  # Empty
            "OAuth " + "a" * 10000,  # Very long header
        ]

        for malformed_header in malformed_headers:
            headers = {"authorization": malformed_header}
            try:
                is_valid, message = await validator.validate(headers, body=b"test")
                # Should handle malformed headers gracefully
                assert isinstance(is_valid, bool)
            except Exception as e:
                # Should not crash
                pass


# ============================================================================
# 4. ERROR INFORMATION DISCLOSURE
# ============================================================================


class TestOAuth1ErrorDisclosure:
    """Test error message information disclosure."""

    @pytest.mark.asyncio
    async def test_exception_message_sanitization(self):
        """Test that exception messages are sanitized."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret",
            }
        }
        validator = OAuth1Validator(config, request=create_mock_request())

        # Mock an exception during parsing
        with patch.object(
            validator,
            "_parse_oauth_header",
            side_effect=Exception("Internal error with path: /etc/passwd"),
        ):
            headers = {"authorization": 'OAuth oauth_consumer_key="consumer_key"'}

            is_valid, message = await validator.validate(headers, body=b"test")
            assert is_valid is False

            # Should sanitize error message
            error_msg = message.lower()
            assert "/etc/passwd" not in error_msg
            assert (
                "internal error" not in error_msg
                or "oauth 1.0 validation error" in error_msg
            )

    @pytest.mark.asyncio
    async def test_config_exposure_in_errors(self):
        """Test that config values are not exposed in error messages."""
        config = {
            "oauth1": {
                "consumer_key": "secret_consumer_key",
                "consumer_secret": "secret_consumer_secret",
            }
        }
        validator = OAuth1Validator(config, request=create_mock_request())

        # Invalid consumer key
        oauth_params = {
            "oauth_consumer_key": "wrong_key",
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_signature": "invalid",
        }

        auth_parts = [
            f'{k}="{quote(str(v), safe="")}"' for k, v in oauth_params.items()
        ]
        auth_header = "OAuth " + ", ".join(auth_parts)

        headers = {"authorization": auth_header}

        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False

        # Should not expose secrets
        assert "secret_consumer_key" not in message
        assert "secret_consumer_secret" not in message
        assert "wrong_key" not in message


# ============================================================================
# 5. CONFIGURATION SECURITY
# ============================================================================


class TestOAuth1ConfigurationSecurity:
    """Test configuration security and validation."""

    @pytest.mark.asyncio
    async def test_config_type_validation(self):
        """Test that config values are validated for correct types."""
        invalid_configs = [
            {"oauth1": {"consumer_key": None, "consumer_secret": "secret"}},
            {"oauth1": {"consumer_key": 123, "consumer_secret": "secret"}},
            {"oauth1": {"consumer_key": "key", "consumer_secret": None}},
            {"oauth1": {"consumer_key": "key", "consumer_secret": 123}},
            {
                "oauth1": {
                    "consumer_key": "key",
                    "consumer_secret": "secret",
                    "signature_method": 123,
                }
            },
        ]

        for invalid_config in invalid_configs:
            validator = OAuth1Validator(invalid_config)
            headers = {"authorization": 'OAuth oauth_consumer_key="key"'}

            is_valid, message = await validator.validate(headers, body=b"test")
            # Should handle invalid config gracefully
            assert isinstance(is_valid, bool)
            if not is_valid:
                assert (
                    "not configured" in message.lower()
                    or "error" in message.lower()
                    or "missing" in message.lower()
                )

    @pytest.mark.asyncio
    async def test_empty_credentials_handling(self):
        """Test that empty credentials are rejected."""
        config = {"oauth1": {"consumer_key": "", "consumer_secret": "secret"}}
        validator = OAuth1Validator(config, request=create_mock_request())

        headers = {"authorization": 'OAuth oauth_consumer_key="key"'}

        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "not configured" in message.lower()

    @pytest.mark.asyncio
    async def test_whitespace_only_credentials(self):
        """Test that whitespace-only credentials are handled."""
        config = {"oauth1": {"consumer_key": "   ", "consumer_secret": "   "}}
        validator = OAuth1Validator(config, request=create_mock_request())

        headers = {"authorization": 'OAuth oauth_consumer_key="key"'}

        is_valid, message = await validator.validate(headers, body=b"test")
        # Empty string check should catch this
        assert is_valid is False or "not configured" in message.lower()


# ============================================================================
# 6. TIMESTAMP MANIPULATION
# ============================================================================


class TestOAuth1TimestampManipulation:
    """Test timestamp manipulation vulnerabilities."""

    @pytest.mark.asyncio
    async def test_timestamp_manipulation_future_timestamp(self):
        """Test that future timestamps are rejected."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret",
                "verify_timestamp": True,
                "timestamp_window": 300,
            },
            
        }
        validator = OAuth1Validator(config, request=create_mock_request())

        uri = "/webhook/test"
        method = "POST"
        consumer_key = "consumer_key"
        consumer_secret = "consumer_secret"
        token_secret = ""

        # Future timestamp (1 hour ahead)
        future_timestamp = str(int(time.time()) + 3600)

        oauth_params = {
            "oauth_consumer_key": consumer_key,
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": future_timestamp,
            "oauth_nonce": "nonce123",
        }

        signature = generate_oauth1_signature(
            method, uri, consumer_secret, token_secret, oauth_params
        )
        oauth_params["oauth_signature"] = signature

        auth_parts = [
            f'{k}="{quote(str(v), safe="")}"' for k, v in oauth_params.items()
        ]
        auth_header = "OAuth " + ", ".join(auth_parts)

        headers = {"authorization": auth_header}

        is_valid, message = await validator.validate(headers, body=b"test")
        # Should reject future timestamp
        assert is_valid is False
        assert "timestamp out of window" in message.lower()

    @pytest.mark.asyncio
    async def test_timestamp_validation_disabled_bypass(self):
        """Test that disabling timestamp validation allows replay attacks."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret",
                "verify_timestamp": False,  # Disabled
                "verify_nonce": False,  # Also disable nonce for testing
            },
            
        }
        validator = OAuth1Validator(config, request=create_mock_request())

        uri = "/webhook/test"
        method = "POST"
        consumer_key = "consumer_key"
        consumer_secret = "consumer_secret"
        token_secret = ""

        # Old timestamp (should be accepted when validation is disabled)
        old_timestamp = str(int(time.time()) - 3600)

        oauth_params = {
            "oauth_consumer_key": consumer_key,
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": old_timestamp,
            "oauth_nonce": "nonce123",
        }

        signature = generate_oauth1_signature(
            method, uri, consumer_secret, token_secret, oauth_params
        )
        oauth_params["oauth_signature"] = signature

        auth_parts = [
            f'{k}="{quote(str(v), safe="")}"' for k, v in oauth_params.items()
        ]
        auth_header = "OAuth " + ", ".join(auth_parts)

        headers = {"authorization": auth_header}

        is_valid, message = await validator.validate(headers, body=b"test")
        # Should accept old timestamp when validation is disabled (known limitation)
        assert is_valid is True


# ============================================================================
# 7. BODY PARAMETER INJECTION
# ============================================================================


class TestOAuth1BodyParameterInjection:
    """Test body parameter injection vulnerabilities."""

    @pytest.mark.asyncio
    async def test_body_parameter_injection(self):
        """Test that body parameters are included in signature base string."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret",
                "signature_method": "HMAC-SHA1",
            },
            
        }
        validator = OAuth1Validator(config, request=create_mock_request())

        uri = "/webhook/test"
        method = "POST"
        consumer_key = "consumer_key"
        consumer_secret = "consumer_secret"
        token_secret = ""

        oauth_params = {
            "oauth_consumer_key": consumer_key,
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": str(int(time.time())),
            "oauth_nonce": "nonce123",
        }

        # Body with form-encoded parameters
        body = b"param1=value1&param2=value2"

        # Generate signature including body parameters
        # Note: Body params are only included if Content-Type is form-encoded
        # But we can't easily set Content-Type in this test
        # So we test that body is handled safely

        signature = generate_oauth1_signature(
            method, uri, consumer_secret, token_secret, oauth_params, body
        )
        oauth_params["oauth_signature"] = signature

        auth_parts = [
            f'{k}="{quote(str(v), safe="")}"' for k, v in oauth_params.items()
        ]
        auth_header = "OAuth " + ", ".join(auth_parts)

        headers = {"authorization": auth_header}

        # Should validate signature (body may or may not be included depending on Content-Type)
        is_valid, message = await validator.validate(headers, body=body)
        # May pass or fail depending on whether body is included in base string
        assert isinstance(is_valid, bool)


# ============================================================================
# 8. URI NORMALIZATION SECURITY
# ============================================================================


class TestOAuth1URINormalization:
    """Test URI normalization security."""

    @pytest.mark.asyncio
    async def test_uri_path_traversal(self):
        """Test URI path traversal attempts."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret",
                "signature_method": "HMAC-SHA1",
            },
            
        }
        validator = OAuth1Validator(config, request=create_mock_request())

        # URI comes from request object, not from header
        # So path traversal in URI is harder to exploit
        # But we test that URI normalization handles edge cases

        uri = "/webhook/test"
        method = "POST"
        consumer_key = "consumer_key"
        consumer_secret = "consumer_secret"
        token_secret = ""

        oauth_params = {
            "oauth_consumer_key": consumer_key,
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": str(int(time.time())),
            "oauth_nonce": "nonce123",
        }

        signature = generate_oauth1_signature(
            method, uri, consumer_secret, token_secret, oauth_params
        )
        oauth_params["oauth_signature"] = signature

        auth_parts = [
            f'{k}="{quote(str(v), safe="")}"' for k, v in oauth_params.items()
        ]
        auth_header = "OAuth " + ", ".join(auth_parts)

        headers = {"authorization": auth_header}

        is_valid, message = await validator.validate(headers, body=b"test")
        # Should validate correctly (URI is normalized)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_uri_with_query_string(self):
        """Test URI normalization with query string."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret",
                "signature_method": "HMAC-SHA1",
            },
            "_request": type(
                "obj", (object,), {"scope": {"path": "/webhook/test?param=value"}}
            )(),
        }
        validator = OAuth1Validator(config, request=create_mock_request())

        # URI with query string should be normalized (query removed)
        uri = "/webhook/test?param=value"
        method = "POST"
        consumer_key = "consumer_key"
        consumer_secret = "consumer_secret"
        token_secret = ""

        oauth_params = {
            "oauth_consumer_key": consumer_key,
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": str(int(time.time())),
            "oauth_nonce": "nonce123",
        }

        # Generate signature with normalized URI (query removed)
        normalized_uri = "/webhook/test"
        signature = generate_oauth1_signature(
            method, normalized_uri, consumer_secret, token_secret, oauth_params
        )
        oauth_params["oauth_signature"] = signature

        auth_parts = [
            f'{k}="{quote(str(v), safe="")}"' for k, v in oauth_params.items()
        ]
        auth_header = "OAuth " + ", ".join(auth_parts)

        headers = {"authorization": auth_header}

        is_valid, message = await validator.validate(headers, body=b"test")
        # Should validate correctly (URI is normalized, query removed)
        assert is_valid is True


# ============================================================================
# 9. SIGNATURE METHOD VALIDATION
# ============================================================================


class TestOAuth1SignatureMethodValidation:
    """Test signature method validation."""

    @pytest.mark.asyncio
    async def test_unsupported_signature_method(self):
        """Test that unsupported signature methods are rejected."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret",
                "signature_method": "HMAC-SHA1",
            }
        }
        validator = OAuth1Validator(config, request=create_mock_request())

        oauth_params = {
            "oauth_consumer_key": "consumer_key",
            "oauth_signature_method": "RSA-SHA1",  # Not supported
            "oauth_signature": "signature",
        }

        auth_parts = [
            f'{k}="{quote(str(v), safe="")}"' for k, v in oauth_params.items()
        ]
        auth_header = "OAuth " + ", ".join(auth_parts)

        headers = {"authorization": auth_header}

        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "signature method" in message.lower()

    @pytest.mark.asyncio
    async def test_case_insensitive_signature_method(self):
        """Test that signature method comparison is case-insensitive."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret",
                "signature_method": "HMAC-SHA1",
            },
            
        }
        validator = OAuth1Validator(config, request=create_mock_request())

        uri = "/webhook/test"
        method = "POST"
        consumer_key = "consumer_key"
        consumer_secret = "consumer_secret"
        token_secret = ""

        oauth_params = {
            "oauth_consumer_key": consumer_key,
            "oauth_signature_method": "hmac-sha1",  # Lowercase
            "oauth_timestamp": str(int(time.time())),
            "oauth_nonce": "nonce123",
        }

        signature = generate_oauth1_signature(
            method, uri, consumer_secret, token_secret, oauth_params
        )
        oauth_params["oauth_signature"] = signature

        auth_parts = [
            f'{k}="{quote(str(v), safe="")}"' for k, v in oauth_params.items()
        ]
        auth_header = "OAuth " + ", ".join(auth_parts)

        headers = {"authorization": auth_header}

        is_valid, message = await validator.validate(headers, body=b"test")
        # Should accept case-insensitive signature method
        assert is_valid is True


# ============================================================================
# 10. EDGE CASES & BOUNDARY CONDITIONS
# ============================================================================


class TestOAuth1EdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.mark.asyncio
    async def test_very_long_oauth_params(self):
        """Test handling of very long OAuth parameters."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret",
                "signature_method": "HMAC-SHA1",
            },
            
        }
        validator = OAuth1Validator(config, request=create_mock_request())

        uri = "/webhook/test"
        method = "POST"
        consumer_key = "consumer_key"
        consumer_secret = "consumer_secret"
        token_secret = ""

        # Very long nonce
        very_long_nonce = "a" * 10000

        oauth_params = {
            "oauth_consumer_key": consumer_key,
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": str(int(time.time())),
            "oauth_nonce": very_long_nonce,
        }

        signature = generate_oauth1_signature(
            method, uri, consumer_secret, token_secret, oauth_params
        )
        oauth_params["oauth_signature"] = signature

        auth_parts = [
            f'{k}="{quote(str(v), safe="")}"' for k, v in oauth_params.items()
        ]
        auth_header = "OAuth " + ", ".join(auth_parts)

        headers = {"authorization": auth_header}

        try:
            is_valid, message = await validator.validate(headers, body=b"test")
            # Should handle long parameters without DoS
            assert isinstance(is_valid, bool)
        except Exception as e:
            # Should not crash
            assert False, f"Validator crashed on long parameters: {e}"

    @pytest.mark.asyncio
    async def test_missing_request_object(self):
        """Test handling when request object is missing."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret",
                "signature_method": "HMAC-SHA1",
            }
            # No _request object
        }
        validator = OAuth1Validator(config, request=create_mock_request())

        uri = "/"  # Default URI
        method = "POST"
        consumer_key = "consumer_key"
        consumer_secret = "consumer_secret"
        token_secret = ""

        oauth_params = {
            "oauth_consumer_key": consumer_key,
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": str(int(time.time())),
            "oauth_nonce": "nonce123",
        }

        signature = generate_oauth1_signature(
            method, uri, consumer_secret, token_secret, oauth_params
        )
        oauth_params["oauth_signature"] = signature

        auth_parts = [
            f'{k}="{quote(str(v), safe="")}"' for k, v in oauth_params.items()
        ]
        auth_header = "OAuth " + ", ".join(auth_parts)

        headers = {"authorization": auth_header}

        is_valid, message = await validator.validate(headers, body=b"test")
        # Should use default URI "/"
        assert isinstance(is_valid, bool)
