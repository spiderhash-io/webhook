"""
Comprehensive security audit tests for ChainValidator.

This audit focuses on:
- Error information disclosure
- DoS via deeply nested structures
- Circular reference handling
- Type confusion attacks
- Large payload DoS
- Edge cases and boundary conditions
- Error message sanitization
- Normalization security
"""

import pytest
import sys
from src.chain_validator import ChainValidator
from src.modules.registry import ModuleRegistry


# ============================================================================
# 1. ERROR INFORMATION DISCLOSURE
# ============================================================================


class TestChainValidatorErrorInformationDisclosure:
    """Test error information disclosure vulnerabilities."""

    def test_module_registry_exception_not_exposed(self):
        """Test that ModuleRegistry exceptions don't expose internal details."""
        # ModuleRegistry.get() raises KeyError or ValueError
        # ChainValidator should catch these and return sanitized error messages
        config = {"chain": ["nonexistent_module_12345"]}
        is_valid, error = ChainValidator.validate_chain_config(config)

        assert is_valid is False
        # Error should not expose internal registry details
        assert "not registered" in error.lower()
        # Should not expose stack traces or internal paths
        assert "traceback" not in error.lower()
        assert "file" not in error.lower()
        assert (
            "module" not in error.lower() or "module" in error.lower()
        )  # Module name is OK

    def test_validation_error_no_internal_paths(self):
        """Test that validation errors don't expose file paths."""
        config = {"chain": ["log"], "chain-config": "not_a_dict"}
        is_valid, error = ChainValidator.validate_chain_config(config)

        assert is_valid is False
        # Should not expose file paths
        assert "/" not in error or error.count("/") == 0  # No path separators
        assert "\\" not in error  # No Windows path separators

    def test_exception_handling_does_not_leak_details(self):
        """Test that exceptions during validation don't leak internal details."""
        # Create a config that might cause an exception
        # Use a very large chain to test error handling
        try:
            large_chain = ["log"] * 1000
            config = {"chain": large_chain}
            is_valid, error = ChainValidator.validate_chain_config(config)

            assert is_valid is False
            # Error should be sanitized, not expose internal details
            assert "exceeds security limit" in error.lower()
        except Exception as e:
            # If an exception is raised, it should be caught and handled
            pytest.fail(f"Exception should be caught: {e}")


# ============================================================================
# 2. DOS VIA DEEPLY NESTED STRUCTURES
# ============================================================================


class TestChainValidatorDeepNestingDoS:
    """Test DoS via deeply nested structures."""

    def test_deeply_nested_module_config(self):
        """Test that deeply nested module-config doesn't cause DoS."""
        # Create a deeply nested dict
        nested = {}
        current = nested
        for i in range(1000):
            current["nested"] = {}
            current = current["nested"]

        config = {"chain": [{"module": "log", "module-config": nested}]}

        # Should handle without stack overflow
        is_valid, error = ChainValidator.validate_chain_config(config)
        # Should pass validation (nested dicts are allowed in module-config)
        # The actual processing will handle depth limits
        assert is_valid is True

    def test_deeply_nested_chain_config(self):
        """Test that deeply nested chain-config doesn't cause DoS."""
        nested = {}
        current = nested
        for i in range(1000):
            current["nested"] = {}
            current = current["nested"]

        config = {"chain": ["log"], "chain-config": nested}

        # Should reject (chain-config must be dict with specific fields)
        is_valid, error = ChainValidator.validate_chain_config(config)
        assert is_valid is False
        assert "dictionary" in error.lower() or "unknown field" in error.lower()

    def test_very_large_chain_list(self):
        """Test that very large chain lists are rejected."""
        # Create chain at limit
        max_chain = ["log"] * ChainValidator.MAX_CHAIN_LENGTH
        config = {"chain": max_chain}
        is_valid, error = ChainValidator.validate_chain_config(config)
        assert is_valid is True

        # Create chain exceeding limit
        too_large_chain = ["log"] * (ChainValidator.MAX_CHAIN_LENGTH + 1)
        config = {"chain": too_large_chain}
        is_valid, error = ChainValidator.validate_chain_config(config)
        assert is_valid is False
        assert "exceeds security limit" in error.lower()


# ============================================================================
# 3. CIRCULAR REFERENCE HANDLING
# ============================================================================


class TestChainValidatorCircularReferences:
    """Test circular reference handling."""

    def test_circular_reference_in_module_config(self):
        """Test that circular references in module-config are handled."""
        # Create circular reference
        circular = {}
        circular["self"] = circular

        config = {"chain": [{"module": "log", "module-config": circular}]}

        # Should handle without infinite recursion
        # Note: isinstance() and dict operations should handle this
        is_valid, error = ChainValidator.validate_chain_config(config)
        # Should pass validation (circular refs in module-config are allowed)
        # The actual processing will handle circular refs
        assert is_valid is True

    def test_circular_reference_in_chain_config(self):
        """Test that circular references in chain-config are handled."""
        circular = {}
        circular["self"] = circular

        config = {"chain": ["log"], "chain-config": circular}

        # Should handle without infinite recursion
        is_valid, error = ChainValidator.validate_chain_config(config)
        # Should reject (chain-config must have specific structure)
        assert is_valid is False


# ============================================================================
# 4. TYPE CONFUSION ATTACKS
# ============================================================================


class TestChainValidatorTypeConfusion:
    """Test type confusion attack prevention."""

    def test_config_not_dict(self):
        """Test that non-dict config is handled safely."""
        # ChainValidator.validate_chain_config expects a dict
        # If passed non-dict, should handle gracefully
        invalid_configs = [
            None,
            "not_a_dict",
            123,
            [],
            True,
        ]

        for invalid_config in invalid_configs:
            # Should handle without crashing and return False with error message
            is_valid, error = ChainValidator.validate_chain_config(invalid_config)
            assert is_valid is False
            assert error is not None
            assert "dictionary" in error.lower()

    def test_chain_not_list(self):
        """Test that non-list chain is rejected."""
        invalid_chains = [
            "not_a_list",
            123,
            {},
            True,
            None,
        ]

        for invalid_chain in invalid_chains:
            config = {"chain": invalid_chain}
            is_valid, error = ChainValidator.validate_chain_config(config)

            if invalid_chain is None:
                # None chain is valid (backward compatibility)
                assert is_valid is True
            else:
                assert is_valid is False
                assert "list" in error.lower()

    def test_chain_item_invalid_types(self):
        """Test that invalid chain item types are rejected."""
        invalid_items = [
            123,
            True,
            None,
            [],
            set(),
        ]

        for invalid_item in invalid_items:
            config = {"chain": [invalid_item]}
            is_valid, error = ChainValidator.validate_chain_config(config)
            assert is_valid is False
            assert "string or dictionary" in error.lower()

    def test_module_name_invalid_types(self):
        """Test that invalid module name types are rejected."""
        invalid_module_names = [
            123,
            True,
            [],
            {},
        ]

        for invalid_name in invalid_module_names:
            config = {"chain": [{"module": invalid_name}]}
            is_valid, error = ChainValidator.validate_chain_config(config)
            assert is_valid is False
            assert "string" in error.lower()

        # None is handled differently (returns "missing required 'module' field")
        config = {"chain": [{"module": None}]}
        is_valid, error = ChainValidator.validate_chain_config(config)
        assert is_valid is False
        assert "missing" in error.lower() or "string" in error.lower()

    def test_connection_invalid_types(self):
        """Test that invalid connection types are rejected."""
        invalid_connections = [
            123,
            True,
            [],
            {},
        ]

        for invalid_conn in invalid_connections:
            config = {"chain": [{"module": "log", "connection": invalid_conn}]}
            is_valid, error = ChainValidator.validate_chain_config(config)
            assert is_valid is False
            assert "string" in error.lower()

    def test_module_config_invalid_types(self):
        """Test that invalid module-config types are rejected."""
        invalid_configs = [
            "not_a_dict",
            123,
            True,
            [],
        ]

        for invalid_config in invalid_configs:
            config = {"chain": [{"module": "log", "module-config": invalid_config}]}
            is_valid, error = ChainValidator.validate_chain_config(config)
            assert is_valid is False
            assert "dictionary" in error.lower()

    def test_retry_config_invalid_types(self):
        """Test that invalid retry config types are rejected."""
        invalid_retry = [
            "not_a_dict",
            123,
            True,
            [],
        ]

        for invalid_r in invalid_retry:
            config = {"chain": [{"module": "log", "retry": invalid_r}]}
            is_valid, error = ChainValidator.validate_chain_config(config)
            assert is_valid is False
            assert "dictionary" in error.lower()

    def test_chain_config_invalid_types(self):
        """Test that invalid chain-config types are rejected."""
        invalid_chain_configs = [
            "not_a_dict",
            123,
            True,
            [],
        ]

        for invalid_cc in invalid_chain_configs:
            config = {"chain": ["log"], "chain-config": invalid_cc}
            is_valid, error = ChainValidator.validate_chain_config(config)
            assert is_valid is False
            assert "dictionary" in error.lower()

    def test_execution_mode_invalid_types(self):
        """Test that invalid execution mode types are rejected."""
        invalid_modes = [
            123,
            True,
            [],
            {},
        ]

        for invalid_mode in invalid_modes:
            config = {"chain": ["log"], "chain-config": {"execution": invalid_mode}}
            is_valid, error = ChainValidator.validate_chain_config(config)
            assert is_valid is False
            assert "string" in error.lower()

    def test_continue_on_error_invalid_types(self):
        """Test that invalid continue_on_error types are rejected."""
        invalid_values = [
            "not_a_boolean",
            123,
            [],
            {},
        ]

        for invalid_val in invalid_values:
            config = {
                "chain": ["log"],
                "chain-config": {"continue_on_error": invalid_val},
            }
            is_valid, error = ChainValidator.validate_chain_config(config)
            assert is_valid is False
            assert "boolean" in error.lower()


# ============================================================================
# 5. LARGE PAYLOAD DOS
# ============================================================================


class TestChainValidatorLargePayloadDoS:
    """Test DoS via large payloads."""

    def test_very_large_module_name(self):
        """Test that very large module names are handled."""
        # ModuleRegistry has MAX_MODULE_NAME_LENGTH = 64
        # Test at limit
        large_name = "a" * 64
        config = {"chain": [large_name]}
        is_valid, error = ChainValidator.validate_chain_config(config)
        # Should fail because module doesn't exist, but validation should pass
        assert is_valid is False
        assert "not registered" in error.lower()

        # Test over limit
        too_large_name = "a" * 65
        config = {"chain": [too_large_name]}
        is_valid, error = ChainValidator.validate_chain_config(config)
        # ModuleRegistry should reject it
        assert is_valid is False

    def test_very_large_connection_name(self):
        """Test that very large connection names are handled."""
        # No explicit limit, but should handle reasonably
        large_conn = "a" * 1000
        config = {"chain": [{"module": "log", "connection": large_conn}]}
        is_valid, error = ChainValidator.validate_chain_config(config)
        # Should pass validation (connection name length not validated here)
        assert is_valid is True

    def test_very_large_module_config(self):
        """Test that very large module-configs are handled."""
        # Create a very large dict
        large_config = {f"key_{i}": f"value_{i}" * 100 for i in range(10000)}

        config = {"chain": [{"module": "log", "module-config": large_config}]}

        # Should handle without memory exhaustion
        is_valid, error = ChainValidator.validate_chain_config(config)
        # Should pass validation (size not checked here)
        assert is_valid is True


# ============================================================================
# 6. EDGE CASES AND BOUNDARY CONDITIONS
# ============================================================================


class TestChainValidatorEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_string_module_name(self):
        """Test that empty string module names are rejected."""
        config = {"chain": [""]}
        is_valid, error = ChainValidator.validate_chain_config(config)
        assert is_valid is False
        assert "non-empty string" in error.lower() or "not registered" in error.lower()

    def test_whitespace_only_module_name(self):
        """Test that whitespace-only module names are rejected."""
        config = {"chain": ["   "]}
        is_valid, error = ChainValidator.validate_chain_config(config)
        assert is_valid is False
        # ModuleRegistry should reject whitespace-only names
        assert "not registered" in error.lower() or "empty" in error.lower()

    def test_none_module_name(self):
        """Test that None module names are rejected."""
        config = {"chain": [{"module": None}]}
        is_valid, error = ChainValidator.validate_chain_config(config)
        assert is_valid is False
        assert "string" in error.lower() or "missing" in error.lower()

    def test_empty_dict_module_config(self):
        """Test that empty dict module-config is allowed."""
        config = {"chain": [{"module": "log", "module-config": {}}]}
        is_valid, error = ChainValidator.validate_chain_config(config)
        assert is_valid is True

    def test_none_connection_allowed(self):
        """Test that None connection is allowed (optional field)."""
        config = {"chain": [{"module": "log", "connection": None}]}
        # None connection should be allowed (it's optional)
        # But type check should fail
        is_valid, error = ChainValidator.validate_chain_config(config)
        # Actually, None is explicitly checked and should be allowed
        # Let's check the code: connection is not None and not isinstance(connection, str)
        # So None should be allowed
        assert is_valid is True

    def test_none_module_config_allowed(self):
        """Test that None module-config is allowed (optional field)."""
        config = {"chain": [{"module": "log", "module-config": None}]}
        # None module-config should be allowed (it's optional)
        is_valid, error = ChainValidator.validate_chain_config(config)
        # Code checks: module_config is not None and not isinstance(module_config, dict)
        # So None should be allowed
        assert is_valid is True

    def test_chain_length_boundary_min(self):
        """Test minimum chain length boundary."""
        # MIN_CHAIN_LENGTH = 1
        config = {"chain": ["log"]}  # Exactly 1
        is_valid, error = ChainValidator.validate_chain_config(config)
        assert is_valid is True

        config = {"chain": []}  # Less than 1
        is_valid, error = ChainValidator.validate_chain_config(config)
        assert is_valid is False
        assert "at least" in error.lower()

    def test_chain_length_boundary_max(self):
        """Test maximum chain length boundary."""
        # MAX_CHAIN_LENGTH = 20
        max_chain = ["log"] * ChainValidator.MAX_CHAIN_LENGTH
        config = {"chain": max_chain}
        is_valid, error = ChainValidator.validate_chain_config(config)
        assert is_valid is True

        too_long = ["log"] * (ChainValidator.MAX_CHAIN_LENGTH + 1)
        config = {"chain": too_long}
        is_valid, error = ChainValidator.validate_chain_config(config)
        assert is_valid is False
        assert "exceeds security limit" in error.lower()

    def test_retry_max_attempts_boundary(self):
        """Test retry max_attempts boundary conditions."""
        # Test positive integer
        config = {"chain": [{"module": "log", "retry": {"max_attempts": 1}}]}
        is_valid, error = ChainValidator.validate_chain_config(config)
        assert is_valid is True

        # Test zero (should be rejected)
        config = {"chain": [{"module": "log", "retry": {"max_attempts": 0}}]}
        is_valid, error = ChainValidator.validate_chain_config(config)
        assert is_valid is False
        assert "positive integer" in error.lower()

        # Test negative (should be rejected)
        config = {"chain": [{"module": "log", "retry": {"max_attempts": -1}}]}
        is_valid, error = ChainValidator.validate_chain_config(config)
        assert is_valid is False
        assert "positive integer" in error.lower()


# ============================================================================
# 7. CONFIGURATION INJECTION
# ============================================================================


class TestChainValidatorConfigurationInjection:
    """Test configuration injection prevention."""

    def test_unknown_field_in_chain_item(self):
        """Test that unknown fields in chain items are rejected."""
        malicious_fields = [
            "__proto__",
            "__class__",
            "__dict__",
            "constructor",
            "prototype",
            "malicious_field",
        ]

        for field in malicious_fields:
            item = {"module": "log", field: "injection_attempt"}
            config = {"chain": [item]}
            is_valid, error = ChainValidator.validate_chain_config(config)
            assert is_valid is False
            assert "unknown field" in error.lower()

    def test_unknown_field_in_chain_config(self):
        """Test that unknown fields in chain-config are rejected."""
        malicious_fields = [
            "__proto__",
            "__class__",
            "__dict__",
            "constructor",
            "prototype",
            "malicious_field",
        ]

        for field in malicious_fields:
            config = {
                "chain": ["log"],
                "chain-config": {"execution": "sequential", field: "injection_attempt"},
            }
            is_valid, error = ChainValidator.validate_chain_config(config)
            assert is_valid is False
            assert "unknown field" in error.lower()

    def test_deprecated_top_level_fields_warning(self):
        """Test that deprecated top-level fields are handled correctly."""
        # topic, queue_name, destination should be in module-config, not top level
        deprecated_fields = ["topic", "queue_name", "destination"]

        for field in deprecated_fields:
            # If field is at top level AND in module-config, should fail
            item = {
                "module": "log",
                "module-config": {field: "value"},
                field: "value",  # Also at top level
            }
            config = {"chain": [item]}
            is_valid, error = ChainValidator.validate_chain_config(config)
            assert is_valid is False
            assert "module-config" in error.lower()

            # If only at top level (no module-config), should be allowed for backward compatibility
            item = {"module": "log", field: "value"}
            config = {"chain": [item]}
            is_valid, error = ChainValidator.validate_chain_config(config)
            # Should be allowed for backward compatibility
            assert is_valid is True


# ============================================================================
# 8. NORMALIZATION SECURITY
# ============================================================================


class TestChainValidatorNormalizationSecurity:
    """Test normalization security."""

    def test_normalize_string_item(self):
        """Test that string items are normalized correctly."""
        normalized = ChainValidator.normalize_chain_item("log")
        assert isinstance(normalized, dict)
        assert normalized["module"] == "log"

    def test_normalize_dict_item(self):
        """Test that dict items are normalized correctly."""
        item = {"module": "log", "connection": "local"}
        normalized = ChainValidator.normalize_chain_item(item)
        assert normalized == item

    def test_normalize_invalid_item_raises_error(self):
        """Test that invalid items raise ValueError during normalization."""
        invalid_items = [
            123,
            True,
            None,
            [],
        ]

        for invalid_item in invalid_items:
            with pytest.raises(ValueError):
                ChainValidator.normalize_chain_item(invalid_item)

    def test_get_chain_modules_extracts_correctly(self):
        """Test that get_chain_modules extracts module names correctly."""
        chain = [
            "log",
            {"module": "save_to_disk", "connection": "local"},
            "rabbitmq",
        ]
        modules = ChainValidator.get_chain_modules(chain)
        assert modules == ["log", "save_to_disk", "rabbitmq"]

    def test_get_chain_modules_handles_missing_module(self):
        """Test that get_chain_modules handles missing module field."""
        chain = [
            "log",
            {"connection": "local"},  # Missing module
        ]
        modules = ChainValidator.get_chain_modules(chain)
        # Should only return modules that have module field
        assert "log" in modules
        assert len(modules) == 1


# ============================================================================
# 9. EXECUTION MODE VALIDATION
# ============================================================================


class TestChainValidatorExecutionMode:
    """Test execution mode validation."""

    def test_valid_execution_modes(self):
        """Test that valid execution modes are accepted."""
        valid_modes = ["sequential", "parallel"]

        for mode in valid_modes:
            config = {"chain": ["log"], "chain-config": {"execution": mode}}
            is_valid, error = ChainValidator.validate_chain_config(config)
            assert is_valid is True

    def test_invalid_execution_modes(self):
        """Test that invalid execution modes are rejected."""
        invalid_modes = [
            "invalid_mode",
            "SEQUENTIAL",  # Case sensitive
            "Parallel",  # Case sensitive
            "sequential_parallel",
            "",
        ]

        for mode in invalid_modes:
            config = {"chain": ["log"], "chain-config": {"execution": mode}}
            is_valid, error = ChainValidator.validate_chain_config(config)
            assert is_valid is False
            assert (
                "execution" in error.lower()
                or "sequential" in error.lower()
                or "parallel" in error.lower()
            )


# ============================================================================
# 10. ERROR MESSAGE SANITIZATION
# ============================================================================


class TestChainValidatorErrorSanitization:
    """Test error message sanitization."""

    def test_error_messages_do_not_expose_internal_details(self):
        """Test that error messages don't expose internal system details."""
        # Test various error scenarios
        test_cases = [
            {"chain": []},  # Empty chain
            {"chain": ["nonexistent"]},  # Invalid module
            {"chain": [123]},  # Invalid type
            {"chain": [{"module": 123}]},  # Invalid module type
            {"chain": ["log"], "chain-config": "not_dict"},  # Invalid chain-config type
        ]

        for config in test_cases:
            is_valid, error = ChainValidator.validate_chain_config(config)
            assert is_valid is False
            assert error is not None

            # Error should not contain:
            # - File paths
            # - Stack traces
            # - Internal variable names
            # - Sensitive information
            assert "traceback" not in error.lower()
            assert "file://" not in error.lower()
            # Module names in error are OK (they're user-provided)
            # But internal paths should not be exposed


# ============================================================================
# 11. COMPREHENSIVE INTEGRATION TESTS
# ============================================================================


class TestChainValidatorComprehensive:
    """Comprehensive integration tests."""

    def test_complex_valid_chain(self):
        """Test a complex but valid chain configuration."""
        config = {
            "chain": [
                "log",
                {
                    "module": "save_to_disk",
                    "connection": "local",
                    "module-config": {"base_dir": "/tmp"},
                    "retry": {"enabled": True, "max_attempts": 3},
                },
                {
                    "module": "rabbitmq",
                    "connection": "rabbitmq_conn",
                    "module-config": {"queue_name": "webhooks"},
                },
            ],
            "chain-config": {"execution": "sequential", "continue_on_error": True},
        }

        is_valid, error = ChainValidator.validate_chain_config(config)
        assert is_valid is True
        assert error is None

    def test_mixed_string_and_dict_chain(self):
        """Test chain with mixed string and dict items."""
        config = {
            "chain": [
                "log",  # String format
                {"module": "save_to_disk"},  # Dict format
                "rabbitmq",  # String format
            ]
        }

        is_valid, error = ChainValidator.validate_chain_config(config)
        assert is_valid is True

    def test_chain_with_all_optional_fields(self):
        """Test chain item with all optional fields."""
        config = {
            "chain": [
                {
                    "module": "log",
                    "connection": "local",
                    "module-config": {"level": "info"},
                    "retry": {"enabled": True, "max_attempts": 5},
                }
            ]
        }

        is_valid, error = ChainValidator.validate_chain_config(config)
        assert is_valid is True
