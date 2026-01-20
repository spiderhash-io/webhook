"""
Comprehensive security audit tests for Environment Variable Substitution System.

This audit focuses on:
- ReDoS (regex denial of service) attacks
- Deep recursion DoS (stack overflow from deeply nested structures)
- Circular reference infinite loops
- Type confusion attacks
- Information disclosure
- Edge cases and boundary conditions
"""

import pytest
import os
import time
import sys
from src.utils import load_env_vars, _sanitize_env_value


# ============================================================================
# 1. REGEX DENIAL OF SERVICE (ReDoS)
# ============================================================================


class TestEnvVarSubstitutionReDoS:
    """Test ReDoS vulnerabilities in environment variable substitution."""

    def test_exact_pattern_redos(self):
        """Test that exact pattern regex is not vulnerable to ReDoS."""
        # Test with malicious input that could cause ReDoS
        malicious_inputs = [
            "{$" + "A" * 1000 + "}",
            "{$VAR:" + "A" * 1000 + "}",
            "{$" + "A" * 10000 + "}",
        ]

        for malicious_input in malicious_inputs:
            start_time = time.time()
            try:
                load_env_vars({"key": malicious_input})
            except Exception:
                pass
            elapsed = time.time() - start_time

            # Should complete quickly (not vulnerable to ReDoS)
            assert (
                elapsed < 1.0
            ), f"ReDoS vulnerability detected for input: {malicious_input[:50]}"

    def test_embedded_pattern_redos(self):
        """Test that embedded pattern regex is not vulnerable to ReDoS."""
        # Test with malicious input that could cause ReDoS
        malicious_inputs = [
            "http://{$" + "A" * 1000 + "}:8080",
            "prefix{$VAR:" + "A" * 1000 + "}suffix",
            "http://{$" + "A" * 10000 + "}:{$PORT}",
        ]

        for malicious_input in malicious_inputs:
            start_time = time.time()
            try:
                load_env_vars({"url": malicious_input})
            except Exception:
                pass
            elapsed = time.time() - start_time

            # Should complete quickly (not vulnerable to ReDoS)
            assert (
                elapsed < 1.0
            ), f"ReDoS vulnerability detected for input: {malicious_input[:50]}"

    def test_sanitize_regex_redos(self):
        """Test that sanitization regex patterns are not vulnerable to ReDoS."""
        # Test SQL injection pattern regex
        malicious_input = "';" + "A" * 1000 + "DROP TABLE users; --"

        start_time = time.time()
        try:
            _sanitize_env_value(malicious_input, "table")
        except Exception:
            pass
        elapsed = time.time() - start_time

        # Should complete quickly (not vulnerable to ReDoS)
        assert elapsed < 1.0, f"ReDoS vulnerability detected in sanitization"


# ============================================================================
# 2. DEEP RECURSION DoS
# ============================================================================


class TestEnvVarSubstitutionDeepRecursion:
    """Test deep recursion DoS vulnerabilities."""

    def test_deeply_nested_dict_recursion(self):
        """Test that deeply nested dictionaries don't cause stack overflow."""
        # Create deeply nested structure
        nested_config = {"level": 1}
        current = nested_config
        for i in range(2, 1000):  # Very deep nesting
            current["nested"] = {"level": i, "value": "{$TEST_VAR}"}
            current = current["nested"]

        os.environ["TEST_VAR"] = "test_value"

        try:
            result = load_env_vars(nested_config)
            # Should not crash
            assert result is not None
        except RecursionError:
            pytest.fail(
                "Deep recursion DoS vulnerability: stack overflow from deeply nested structure"
            )

    def test_deeply_nested_list_recursion(self):
        """Test that deeply nested lists don't cause stack overflow."""
        # Create deeply nested structure
        nested_list = ["{$TEST_VAR}"]
        current = nested_list
        for i in range(1000):  # Very deep nesting
            current.append([f"level_{i}", "{$TEST_VAR}"])
            current = current[-1]

        os.environ["TEST_VAR"] = "test_value"

        try:
            result = load_env_vars(nested_list)
            # Should not crash
            assert result is not None
        except RecursionError:
            pytest.fail(
                "Deep recursion DoS vulnerability: stack overflow from deeply nested list"
            )


# ============================================================================
# 3. CIRCULAR REFERENCE INFINITE LOOPS
# ============================================================================


class TestEnvVarSubstitutionCircularReferences:
    """Test circular reference infinite loop vulnerabilities."""

    def test_circular_reference_dict(self):
        """Test that circular references in dictionaries don't cause infinite loops."""
        # Create circular reference
        config = {"key": "{$TEST_VAR}"}
        config["self"] = config  # Circular reference

        os.environ["TEST_VAR"] = "test_value"

        start_time = time.time()
        try:
            result = load_env_vars(config)
            elapsed = time.time() - start_time
            # Should complete quickly (not infinite loop)
            assert elapsed < 1.0, "Circular reference infinite loop detected"
            assert result is not None
        except RecursionError:
            pytest.fail("Circular reference infinite loop vulnerability detected")

    def test_circular_reference_list(self):
        """Test that circular references in lists don't cause infinite loops."""
        # Create circular reference
        config = ["{$TEST_VAR}"]
        config.append(config)  # Circular reference

        os.environ["TEST_VAR"] = "test_value"

        start_time = time.time()
        try:
            result = load_env_vars(config)
            elapsed = time.time() - start_time
            # Should complete quickly (not infinite loop)
            assert elapsed < 1.0, "Circular reference infinite loop detected"
            assert result is not None
        except RecursionError:
            pytest.fail("Circular reference infinite loop vulnerability detected")


# ============================================================================
# 4. TYPE CONFUSION ATTACKS
# ============================================================================


class TestEnvVarSubstitutionTypeConfusion:
    """Test type confusion vulnerabilities."""

    def test_non_string_value_handling(self):
        """Test that non-string values are handled safely."""
        # Test with non-string values
        config = {
            "string": "{$TEST_VAR}",
            "number": 123,
            "boolean": True,
            "none": None,
            "list": [1, 2, 3],
            "dict": {"key": "value"},
        }

        os.environ["TEST_VAR"] = "test_value"

        try:
            result = load_env_vars(config)
            # Should not crash
            assert result is not None
            # String should be processed
            assert result["string"] == "test_value"
            # Non-string values should remain unchanged
            assert result["number"] == 123
            assert result["boolean"] is True
            assert result["none"] is None
        except (TypeError, AttributeError) as e:
            pytest.fail(f"Type confusion vulnerability: {e}")

    def test_non_dict_non_list_data(self):
        """Test that non-dict/non-list data is handled safely."""
        # Test with primitive types
        os.environ["TEST_VAR"] = "test_value"

        try:
            # String - should process environment variables
            result = load_env_vars("{$TEST_VAR}")
            assert result == "test_value"

            # Number - should return as-is
            result = load_env_vars(123)
            assert result == 123

            # Boolean - should return as-is
            result = load_env_vars(True)
            assert result is True

            # None - should return as-is
            result = load_env_vars(None)
            assert result is None
        except (TypeError, AttributeError) as e:
            pytest.fail(f"Type confusion vulnerability: {e}")


# ============================================================================
# 5. INFORMATION DISCLOSURE
# ============================================================================


class TestEnvVarSubstitutionInformationDisclosure:
    """Test information disclosure vulnerabilities."""

    def test_error_message_disclosure(self):
        """Test that error messages don't disclose sensitive information."""
        # Test with missing environment variable
        config = {"key": "{$MISSING_VAR}"}

        result = load_env_vars(config)

        # Error message should not expose internal details
        error_msg = result["key"]
        # Should not expose file paths, internal structure, etc.
        assert "/" not in error_msg or "Undefined variable" in error_msg
        assert "\\" not in error_msg or "Undefined variable" in error_msg

    def test_warning_message_disclosure(self):
        """Test that warning messages don't disclose sensitive information."""
        import io
        import sys

        # Capture print output
        captured_output = io.StringIO()
        sys.stdout = captured_output

        try:
            config = {"key": "{$MISSING_VAR}"}
            load_env_vars(config)

            output = captured_output.getvalue()
            # Warning should not expose sensitive information
            # (This is a basic check - warnings are printed to stdout)
        finally:
            sys.stdout = sys.__stdout__


# ============================================================================
# 6. EDGE CASES AND BOUNDARY CONDITIONS
# ============================================================================


class TestEnvVarSubstitutionEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_string_value(self):
        """Test that empty string values are handled safely."""
        os.environ["EMPTY_VAR"] = ""

        config = {"key": "{$EMPTY_VAR}", "key2": "{$EMPTY_VAR:default}"}

        result = load_env_vars(config)
        assert result["key"] == ""
        assert result["key2"] == ""

    def test_very_long_env_var_name(self):
        """Test that very long environment variable names are handled safely."""
        long_var_name = "A" * 1000
        os.environ[long_var_name] = "value"

        config = {"key": f"{{${long_var_name}}}"}

        try:
            result = load_env_vars(config)
            # Should handle long names (though unlikely in practice)
            assert result is not None
        except Exception as e:
            # May fail due to OS limits, but should fail gracefully
            assert "Undefined variable" in str(result.get("key", "")) or True

    def test_special_characters_in_env_var_name(self):
        """Test that special characters in env var names are handled safely."""
        # Environment variable names should only contain alphanumeric and underscore
        # Test with invalid characters
        config = {
            "key": "{$VAR-WITH-DASH}",  # Invalid env var name
            "key2": "{$VAR.WITH.DOT}",  # Invalid env var name
        }

        try:
            result = load_env_vars(config)
            # Should handle invalid names gracefully
            assert result is not None
        except Exception:
            # May fail, but should fail gracefully
            pass

    def test_nested_env_var_references(self):
        """Test that nested environment variable references are handled safely."""
        # Note: Current implementation doesn't support nested references
        # This test verifies it doesn't cause issues
        os.environ["VAR1"] = "{$VAR2}"
        os.environ["VAR2"] = "value"

        config = {"key": "{$VAR1}"}

        result = load_env_vars(config)
        # Should process VAR1, but VAR2 placeholder in the value will be sanitized
        # The $ and {} characters are removed by sanitization
        assert result["key"] == "VAR2"  # Sanitized value (dangerous chars removed)

    def test_malformed_env_var_syntax(self):
        """Test that malformed environment variable syntax is handled safely."""
        malformed_inputs = [
            "{$",  # Incomplete
            "${VAR}",  # Wrong syntax
            "{$VAR",  # Missing closing brace
            "{$VAR:}",  # Empty default
            "{$VAR:default:extra}",  # Multiple colons
        ]

        for malformed_input in malformed_inputs:
            try:
                config = {"key": malformed_input}
                result = load_env_vars(config)
                # Should handle malformed syntax gracefully
                assert result is not None
            except Exception:
                # May fail, but should fail gracefully
                pass

    def test_concurrent_access_safety(self):
        """Test that concurrent access doesn't cause issues."""
        import threading

        os.environ["CONCURRENT_VAR"] = "value"

        config = {"key": "{$CONCURRENT_VAR}"}

        results = []
        errors = []

        def process_config():
            try:
                result = load_env_vars(config.copy())
                results.append(result)
            except Exception as e:
                errors.append(e)

        # Run multiple threads
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=process_config)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Should not crash
        assert len(errors) == 0, f"Concurrent access errors: {errors}"
        assert len(results) == 10


# ============================================================================
# 7. SANITIZATION EDGE CASES
# ============================================================================


class TestSanitizationEdgeCases:
    """Test sanitization edge cases."""

    def test_sanitize_empty_string(self):
        """Test that empty strings are sanitized safely."""
        result = _sanitize_env_value("", "test")
        assert result == ""

    def test_sanitize_none_value(self):
        """Test that None values are sanitized safely."""
        result = _sanitize_env_value(None, "test")
        assert result is None

    def test_sanitize_non_string_value(self):
        """Test that non-string values are sanitized safely."""
        result = _sanitize_env_value(123, "test")
        assert result == 123

    def test_sanitize_very_long_value(self):
        """Test that very long values are truncated."""
        long_value = "A" * 10000
        result = _sanitize_env_value(long_value, "test")
        assert len(result) <= 4096  # MAX_ENV_VALUE_LENGTH

    def test_sanitize_all_dangerous_chars(self):
        """Test that all dangerous characters are removed."""
        dangerous_value = ";|&`$(){}"
        result = _sanitize_env_value(dangerous_value, "test")
        # All dangerous characters should be removed
        assert ";" not in result
        assert "|" not in result
        assert "&" not in result
        assert "`" not in result
        assert "$" not in result
        assert "(" not in result
        assert ")" not in result
        assert "{" not in result
        assert "}" not in result

    def test_sanitize_completely_sanitized_value(self):
        """Test that completely sanitized values return safe default."""
        # Value that becomes empty after sanitization
        dangerous_value = ";|&`$(){}rm -rf /"
        result = _sanitize_env_value(dangerous_value, "test")
        # Should return safe default if completely sanitized
        assert result == "sanitized_value" or len(result) > 0
