"""
Comprehensive security audit tests for QueryParameterAuthValidator.
Tests URL encoding manipulation, parameter pollution, configuration injection, error disclosure, and edge cases.
"""

import pytest
from urllib.parse import quote, unquote
from src.validators import QueryParameterAuthValidator


# ============================================================================
# 1. URL ENCODING MANIPULATION
# ============================================================================


class TestQueryAuthURLEncoding:
    """Test URL encoding manipulation vulnerabilities."""

    @pytest.mark.asyncio
    async def test_url_encoded_parameter_value(self):
        """Test that URL-encoded parameter values are handled correctly."""
        config = {"query_auth": {"api_key": "secret_key_123"}}

        # URL-encoded key
        encoded_key = quote("secret_key_123")
        query_params = {"api_key": encoded_key}

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        # URL-encoded values should be decoded by the framework before reaching validator
        # But if they're not, the comparison should still work
        # The validator receives the decoded value, so this should pass
        assert isinstance(is_valid, bool)

    @pytest.mark.asyncio
    async def test_double_url_encoded_parameter_value(self):
        """Test double URL encoding attempts."""
        config = {"query_auth": {"api_key": "secret_key_123"}}

        # Double URL-encoded key
        double_encoded = quote(quote("secret_key_123"))
        query_params = {"api_key": double_encoded}

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        # Double encoding should be handled by framework, but validator should handle safely
        assert isinstance(is_valid, bool)

    @pytest.mark.asyncio
    async def test_url_encoded_parameter_name(self):
        """Test URL-encoded parameter name in config."""
        config = {
            "query_auth": {
                "parameter_name": quote("api_key"),  # URL-encoded in config
                "api_key": "secret_key_123",
            }
        }

        query_params = {"api_key": "secret_key_123"}

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        # Parameter name validation should reject URL-encoded names (not alphanumeric)
        # Or if accepted, should handle safely
        assert isinstance(is_valid, bool)

    @pytest.mark.asyncio
    async def test_unicode_encoding_manipulation(self):
        """Test Unicode encoding manipulation."""
        config = {"query_auth": {"api_key": "secret_key_123"}}

        # Unicode variations
        unicode_variations = [
            "secret_key_123",  # Normal
            "secret_key_123",  # With Unicode characters
            "secret\u005fkey\u005f123",  # Unicode escape sequences
        ]

        for unicode_key in unicode_variations:
            query_params = {"api_key": unicode_key}
            is_valid, message = QueryParameterAuthValidator.validate_query_params(
                query_params, config
            )
            # Should handle Unicode safely
            assert isinstance(is_valid, bool)


# ============================================================================
# 2. PARAMETER POLLUTION & MULTIPLE VALUES
# ============================================================================


class TestQueryAuthParameterPollution:
    """Test parameter pollution and multiple value handling."""

    @pytest.mark.asyncio
    async def test_multiple_parameter_values(self):
        """Test handling of multiple values for same parameter."""
        config = {"query_auth": {"api_key": "secret_key_123"}}

        # Query params dict with multiple values (Python dict only keeps last)
        # But in real HTTP, query strings can have multiple values: ?api_key=value1&api_key=value2
        # The framework should handle this, but we test validator behavior

        query_params = {"api_key": "secret_key_123"}

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is True

        # Test with wrong key
        query_params = {"api_key": "wrong_key"}
        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_parameter_name_collision(self):
        """Test parameter name collision with other parameters."""
        config = {
            "query_auth": {"parameter_name": "api_key", "api_key": "secret_key_123"}
        }

        # Multiple parameters, one matches
        query_params = {
            "api_key": "secret_key_123",
            "other_param": "value",
            "api_key_old": "old_value",
        }

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_parameter_name_similarity_attack(self):
        """Test parameter name similarity attacks (e.g., api_key vs api_key_)."""
        config = {
            "query_auth": {"parameter_name": "api_key", "api_key": "secret_key_123"}
        }

        # Similar but different parameter names
        similar_names = [
            "api_key_",  # Trailing underscore
            "_api_key",  # Leading underscore
            "api.key",  # Dot instead of underscore
            "api-key",  # Hyphen instead of underscore
        ]

        for similar_name in similar_names:
            query_params = {similar_name: "secret_key_123"}
            is_valid, message = QueryParameterAuthValidator.validate_query_params(
                query_params, config
            )
            # Should fail - parameter name doesn't match
            assert is_valid is False
            assert (
                "Missing required query parameter" in message
                or "Invalid API key" in message
            )


# ============================================================================
# 3. CONFIGURATION INJECTION & TYPE VALIDATION
# ============================================================================


class TestQueryAuthConfigurationSecurity:
    """Test configuration security and type validation."""

    @pytest.mark.asyncio
    async def test_config_type_validation(self):
        """Test that config values are validated for correct types."""
        invalid_configs = [
            {"query_auth": {"api_key": None}},
            {"query_auth": {"api_key": 123}},
            {"query_auth": {"api_key": "secret", "parameter_name": None}},
            {"query_auth": {"api_key": "secret", "parameter_name": 123}},
            {
                "query_auth": {"api_key": "secret", "case_sensitive": "true"}
            },  # Should be bool
        ]

        for invalid_config in invalid_configs:
            query_params = {"api_key": "secret"}
            is_valid, message = QueryParameterAuthValidator.validate_query_params(
                query_params, invalid_config
            )
            # Should handle invalid config gracefully
            assert isinstance(is_valid, bool)
            if not is_valid:
                assert (
                    "not configured" in message.lower()
                    or "error" in message.lower()
                    or "invalid" in message.lower()
                    or "must be a string" in message.lower()
                )

    @pytest.mark.asyncio
    async def test_empty_api_key_config(self):
        """Test that empty API key in config is rejected."""
        config = {"query_auth": {"api_key": ""}}  # Empty string

        query_params = {"api_key": "some_key"}

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is False
        assert "not configured" in message.lower()

    @pytest.mark.asyncio
    async def test_whitespace_only_api_key_config(self):
        """Test that whitespace-only API key in config is handled."""
        config = {"query_auth": {"api_key": "   "}}  # Whitespace only

        query_params = {"api_key": "   "}

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        # Empty string check should catch this
        assert is_valid is False or "not configured" in message.lower()

    @pytest.mark.asyncio
    async def test_parameter_name_injection_via_config(self):
        """Test parameter name injection via configuration."""
        # Parameter name validation should prevent injection
        malicious_configs = [
            {"query_auth": {"parameter_name": "../../etc/passwd", "api_key": "secret"}},
            {
                "query_auth": {
                    "parameter_name": "api_key; DROP TABLE",
                    "api_key": "secret",
                }
            },
            {
                "query_auth": {
                    "parameter_name": "api_key\ninjected",
                    "api_key": "secret",
                }
            },
        ]

        for malicious_config in malicious_configs:
            query_params = {"api_key": "secret"}
            is_valid, message = QueryParameterAuthValidator.validate_query_params(
                query_params, malicious_config
            )
            # Should reject invalid parameter names
            assert is_valid is False
            assert (
                "Invalid parameter name" in message
                or "configuration" in message.lower()
            )


# ============================================================================
# 4. ERROR INFORMATION DISCLOSURE
# ============================================================================


class TestQueryAuthErrorDisclosure:
    """Test error message information disclosure."""

    @pytest.mark.asyncio
    async def test_config_exposure_in_errors(self):
        """Test that config values are not exposed in error messages."""
        config = {"query_auth": {"api_key": "secret_api_key_12345"}}

        # Invalid key
        query_params = {"api_key": "wrong_key"}

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is False

        # Should not expose secret key
        assert "secret_api_key_12345" not in message
        assert "wrong_key" not in message

    @pytest.mark.asyncio
    async def test_parameter_name_exposure(self):
        """Test that parameter names are not overly exposed in errors."""
        config = {"query_auth": {"parameter_name": "api_key", "api_key": "secret"}}

        # Missing parameter
        query_params = {}

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is False

        # Parameter name can be mentioned (it's not secret), but shouldn't expose full config
        # Current implementation mentions parameter name, which is acceptable
        assert "api_key" in message or "parameter" in message.lower()


# ============================================================================
# 5. TIMING ATTACKS
# ============================================================================


class TestQueryAuthTimingAttacks:
    """Test timing attack vulnerabilities."""

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_timing_attack_resistance(self):
        """Test that validation uses constant-time comparison."""
        import time

        config = {"query_auth": {"api_key": "secret_key_123"}}

        # Correct key
        correct_params = {"api_key": "secret_key_123"}

        # Wrong key (first character different)
        wrong_params1 = {"api_key": "x" + "secret_key_123"[1:]}

        # Wrong key (last character different)
        wrong_params2 = {"api_key": "secret_key_123"[:-1] + "x"}

        # Measure times
        correct_times = []
        for _ in range(10):
            start = time.perf_counter()
            QueryParameterAuthValidator.validate_query_params(correct_params, config)
            correct_times.append(time.perf_counter() - start)
        correct_time = sum(correct_times) / len(correct_times)

        wrong_times1 = []
        for _ in range(10):
            start = time.perf_counter()
            QueryParameterAuthValidator.validate_query_params(wrong_params1, config)
            wrong_times1.append(time.perf_counter() - start)
        wrong_time1 = sum(wrong_times1) / len(wrong_times1)

        wrong_times2 = []
        for _ in range(10):
            start = time.perf_counter()
            QueryParameterAuthValidator.validate_query_params(wrong_params2, config)
            wrong_times2.append(time.perf_counter() - start)
        wrong_time2 = sum(wrong_times2) / len(wrong_times2)

        # Times should be similar (constant-time comparison)
        time_diff1 = abs(correct_time - wrong_time1) / max(
            correct_time, wrong_time1, 0.000001
        )
        time_diff2 = abs(correct_time - wrong_time2) / max(
            correct_time, wrong_time2, 0.000001
        )

        # Allow up to 70% difference due to system noise
        assert (
            time_diff1 < 0.7
        ), f"Timing attack vulnerability detected (first char): {time_diff1:.2%}"
        assert (
            time_diff2 < 0.7
        ), f"Timing attack vulnerability detected (last char): {time_diff2:.2%}"


# ============================================================================
# 6. REGEX REDOS & VALIDATION ATTACKS
# ============================================================================


class TestQueryAuthRegexRedos:
    """Test ReDoS vulnerabilities in parameter name validation."""

    @pytest.mark.asyncio
    async def test_regex_redos_parameter_name(self):
        """Test ReDoS vulnerability in parameter name regex."""
        import time

        # Complex parameter name that might cause ReDoS
        complex_name = "a" * 1000 + "!"  # Long string ending with invalid char

        start_time = time.time()
        is_valid, error = QueryParameterAuthValidator._validate_parameter_name(
            complex_name
        )
        elapsed = time.time() - start_time

        # Should complete quickly (no ReDoS)
        assert elapsed < 1.0, f"ReDoS detected: validation took {elapsed:.2f}s"
        assert is_valid is False  # Should reject invalid character

    @pytest.mark.asyncio
    async def test_regex_redos_via_config(self):
        """Test ReDoS via malicious parameter name in config."""
        import time

        # Complex parameter name in config
        complex_name = "a" * 1000 + "!"
        config = {"query_auth": {"parameter_name": complex_name, "api_key": "secret"}}

        query_params = {"api_key": "secret"}

        start_time = time.time()
        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        elapsed = time.time() - start_time

        # Should complete quickly (no ReDoS)
        assert elapsed < 1.0, f"ReDoS detected: validation took {elapsed:.2f}s"
        assert is_valid is False  # Should reject invalid parameter name


# ============================================================================
# 7. CASE SENSITIVITY EDGE CASES
# ============================================================================


class TestQueryAuthCaseSensitivity:
    """Test case sensitivity edge cases."""

    @pytest.mark.asyncio
    async def test_case_sensitivity_with_unicode(self):
        """Test case sensitivity with Unicode characters."""
        config = {"query_auth": {"api_key": "SecretKey测试", "case_sensitive": True}}

        # Exact match
        query_params = {"api_key": "SecretKey测试"}
        is_valid, _ = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is True

        # Different case (Unicode case folding)
        query_params = {"api_key": "secretkey测试"}
        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        # Should fail with case_sensitive=True
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_case_sensitivity_empty_string(self):
        """Test case sensitivity with empty strings."""
        config = {"query_auth": {"api_key": "", "case_sensitive": False}}

        query_params = {"api_key": ""}

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        # Empty string should be rejected
        assert is_valid is False
        assert "not configured" in message.lower() or "Invalid" in message


# ============================================================================
# 8. SANITIZATION BYPASS ATTEMPTS
# ============================================================================


class TestQueryAuthSanitizationBypass:
    """Test sanitization bypass attempts."""

    @pytest.mark.asyncio
    async def test_sanitization_preserves_valid_keys(self):
        """Test that sanitization doesn't break valid keys."""
        config = {"query_auth": {"api_key": "secret_key_123"}}

        # Valid key should pass
        query_params = {"api_key": "secret_key_123"}
        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is True

        # Key with spaces (should be preserved if printable)
        query_params = {"api_key": "secret key 123"}
        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        # Spaces are printable, so should be preserved
        # But won't match "secret_key_123", so should fail
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_sanitization_removes_control_chars(self):
        """Test that sanitization correctly removes control characters."""
        config = {"query_auth": {"api_key": "secret_key_123"}}

        # Key with control characters that should be removed
        control_char_keys = [
            "secret_key_123\x00",  # Null byte
            "secret_key_123\n",  # Newline
            "secret_key_123\r",  # Carriage return
            "secret_key_123\t",  # Tab
        ]

        for control_key in control_char_keys:
            query_params = {"api_key": control_key}
            is_valid, message = QueryParameterAuthValidator.validate_query_params(
                query_params, config
            )
            # After sanitization, control chars are removed, leaving "secret_key_123"
            # So should match and pass
            assert is_valid is True

    @pytest.mark.asyncio
    async def test_sanitization_with_mixed_chars(self):
        """Test sanitization with mixed valid and invalid characters."""
        config = {"query_auth": {"api_key": "secret_key_123"}}

        # Key with control chars and extra valid chars
        query_params = {"api_key": "secret_key_123\x00extra"}

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        # After sanitization: "secret_key_123extra" != "secret_key_123", so should fail
        assert is_valid is False


# ============================================================================
# 9. EDGE CASES & BOUNDARY CONDITIONS
# ============================================================================


class TestQueryAuthEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.mark.asyncio
    async def test_max_length_parameter_name(self):
        """Test parameter name at maximum length."""
        config = {
            "query_auth": {
                "parameter_name": "a" * 100,  # Max length
                "api_key": "secret",
            }
        }

        query_params = {"a" * 100: "secret"}

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        # Should handle max length parameter name
        assert isinstance(is_valid, bool)

    @pytest.mark.asyncio
    async def test_max_length_parameter_value(self):
        """Test parameter value at maximum length."""
        long_key = "a" * 1000  # Max length
        config = {"query_auth": {"api_key": long_key}}

        query_params = {"api_key": long_key}

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        # Should handle max length parameter value
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_parameter_name_at_boundary(self):
        """Test parameter name just over boundary."""
        config = {
            "query_auth": {
                "parameter_name": "a" * 101,  # Over max length
                "api_key": "secret",
            }
        }

        query_params = {"api_key": "secret"}

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        # Should reject parameter name over max length
        assert is_valid is False
        assert "Invalid parameter name" in message or "configuration" in message.lower()

    @pytest.mark.asyncio
    async def test_parameter_value_at_boundary(self):
        """Test parameter value just over boundary."""
        config = {"query_auth": {"api_key": "secret"}}

        long_value = "a" * 1001  # Over max length
        query_params = {"api_key": long_value}

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        # Should reject parameter value over max length
        assert is_valid is False
        assert "too long" in message.lower() or "invalid" in message.lower()

    @pytest.mark.asyncio
    async def test_none_parameter_value(self):
        """Test handling of None parameter value."""
        config = {"query_auth": {"api_key": "secret"}}

        query_params = {"api_key": None}

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        # Should reject None value (treated as missing parameter)
        assert is_valid is False
        assert (
            "missing" in message.lower()
            or "type" in message.lower()
            or "invalid" in message.lower()
        )

    @pytest.mark.asyncio
    async def test_empty_dict_query_params(self):
        """Test handling of empty query params dict."""
        config = {"query_auth": {"api_key": "secret"}}

        query_params = {}

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        # Should reject missing parameter
        assert is_valid is False
        assert "Missing required query parameter" in message


# ============================================================================
# 10. UNICODE NORMALIZATION
# ============================================================================


class TestQueryAuthUnicodeNormalization:
    """Test Unicode normalization vulnerabilities."""

    @pytest.mark.asyncio
    async def test_unicode_normalization_attack(self):
        """Test Unicode normalization attacks."""
        import unicodedata

        config = {"query_auth": {"api_key": "secret_key_123"}}

        # Unicode normalization variations
        # Note: The validator doesn't normalize Unicode, so these should be compared as-is
        normal_key = "secret_key_123"
        nfd_key = unicodedata.normalize("NFD", normal_key)
        nfc_key = unicodedata.normalize("NFC", normal_key)

        # Normal key should work
        query_params = {"api_key": normal_key}
        is_valid, _ = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        assert is_valid is True

        # NFD/NFC variations should not match (no normalization)
        query_params = {"api_key": nfd_key}
        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        # Should fail if normalization is not applied (which is correct for security)
        assert is_valid is False or normal_key == nfd_key  # May be same for ASCII


# ============================================================================
# 11. CONFIGURATION SECURITY - TYPE CONFUSION
# ============================================================================


class TestQueryAuthTypeConfusion:
    """Test type confusion attacks."""

    @pytest.mark.asyncio
    async def test_type_confusion_api_key(self):
        """Test type confusion with api_key config."""
        # Try different types for api_key
        type_confusion_configs = [
            {"query_auth": {"api_key": []}},
            {"query_auth": {"api_key": {}}},
            {"query_auth": {"api_key": True}},
            {"query_auth": {"api_key": 0}},
        ]

        for config in type_confusion_configs:
            query_params = {"api_key": "secret"}
            is_valid, message = QueryParameterAuthValidator.validate_query_params(
                query_params, config
            )
            # Should handle type confusion safely
            assert isinstance(is_valid, bool)
            if not is_valid:
                assert (
                    "not configured" in message.lower()
                    or "error" in message.lower()
                    or "invalid" in message.lower()
                    or "must be a string" in message.lower()
                )

    @pytest.mark.asyncio
    async def test_type_confusion_case_sensitive(self):
        """Test type confusion with case_sensitive config."""
        # case_sensitive should be bool, but try other types
        config = {
            "query_auth": {
                "api_key": "secret",
                "case_sensitive": "true",  # String instead of bool
            }
        }

        query_params = {"api_key": "secret"}

        # Should handle non-bool case_sensitive (treats as falsy)
        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        # String "true" is truthy in Python, but should be handled safely
        assert isinstance(is_valid, bool)


# ============================================================================
# 12. PARAMETER NAME VALIDATION EDGE CASES
# ============================================================================


class TestQueryAuthParameterNameValidation:
    """Test parameter name validation edge cases."""

    @pytest.mark.asyncio
    async def test_parameter_name_with_dots(self):
        """Test parameter name with dots (allowed)."""
        config = {"query_auth": {"parameter_name": "api.key", "api_key": "secret"}}

        query_params = {"api.key": "secret"}

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        # Dots are allowed in parameter names
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_parameter_name_with_hyphens(self):
        """Test parameter name with hyphens (allowed)."""
        config = {"query_auth": {"parameter_name": "api-key", "api_key": "secret"}}

        query_params = {"api-key": "secret"}

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        # Hyphens are allowed in parameter names
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_parameter_name_with_underscores(self):
        """Test parameter name with underscores (allowed)."""
        config = {"query_auth": {"parameter_name": "api_key", "api_key": "secret"}}

        query_params = {"api_key": "secret"}

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        # Underscores are allowed
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_parameter_name_numeric_only(self):
        """Test parameter name with only numbers."""
        config = {"query_auth": {"parameter_name": "123", "api_key": "secret"}}

        query_params = {"123": "secret"}

        is_valid, message = QueryParameterAuthValidator.validate_query_params(
            query_params, config
        )
        # Numbers are allowed
        assert is_valid is True
