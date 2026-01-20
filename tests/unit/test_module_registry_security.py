"""
Security tests for module registry validation.
Tests that module names are properly validated to prevent injection attacks.
"""

import pytest
from src.modules.registry import ModuleRegistry
from src.modules.base import BaseModule


class TestModuleRegistrySecurity:
    """Test suite for module registry validation security."""

    def test_path_traversal_blocked(self):
        """Test that path traversal patterns are blocked."""
        traversal_patterns = [
            "../module",
            "../../module",
            "module/../other",
            "module\\..\\other",
            "module/",
            "module\\",
        ]

        for pattern in traversal_patterns:
            with pytest.raises(ValueError, match="path traversal"):
                ModuleRegistry.get(pattern)

    def test_null_byte_blocked(self):
        """Test that null bytes are blocked."""
        with pytest.raises(ValueError, match="null bytes"):
            ModuleRegistry.get("module\x00name")

    def test_max_length_enforced(self):
        """Test that maximum length is enforced to prevent DoS."""
        # Test exactly at limit (64 chars)
        valid_name = "a" * 64
        # This will fail because it's not registered, but validation should pass
        with pytest.raises(KeyError):
            ModuleRegistry.get(valid_name)  # Should pass validation, fail on lookup

        # Test over limit (65 chars)
        invalid_name = "a" * 65
        with pytest.raises(ValueError, match="too long"):
            ModuleRegistry.get(invalid_name)

    def test_empty_name_rejected(self):
        """Test that empty names are rejected."""
        empty_names = [
            "",
            "   ",
            "\t",
            "\n",
        ]

        for empty_name in empty_names:
            with pytest.raises(ValueError, match="empty|whitespace"):
                ModuleRegistry.get(empty_name)

    def test_must_start_with_alphanumeric(self):
        """Test that module names must start with alphanumeric."""
        invalid_starts = [
            "_module",
            "-module",
        ]

        for invalid_name in invalid_starts:
            with pytest.raises(ValueError, match="start with alphanumeric"):
                ModuleRegistry.get(invalid_name)

    def test_consecutive_special_chars_blocked(self):
        """Test that consecutive underscores or hyphens are blocked."""
        invalid_names = [
            "module--name",
            "module__name",
            "module---name",
            "module___name",
        ]

        for invalid_name in invalid_names:
            with pytest.raises(ValueError, match="consecutive"):
                ModuleRegistry.get(invalid_name)

    def test_only_special_chars_blocked(self):
        """Test that names consisting only of special characters are blocked."""
        invalid_names = [
            "___",
            "---",
            "_-_",
        ]

        for invalid_name in invalid_names:
            # These will be caught by format validation (must start with alphanumeric)
            with pytest.raises(
                ValueError,
                match="start with alphanumeric|only.*underscores|only.*hyphens",
            ):
                ModuleRegistry.get(invalid_name)

    def test_valid_module_names_accepted(self):
        """Test that valid module names pass validation."""
        valid_names = [
            "log",
            "http_webhook",
            "save-to-disk",
            "redis_publish",
            "module123",
            "test-module_123",
        ]

        for valid_name in valid_names:
            # These should pass validation (may fail on lookup if not registered)
            try:
                ModuleRegistry.get(valid_name)
            except KeyError:
                # KeyError is expected for unregistered modules - validation passed
                pass
            except ValueError as e:
                # ValueError means validation failed - this is unexpected
                pytest.fail(f"Valid module name '{valid_name}' was rejected: {e}")

    def test_registered_modules_accessible(self):
        """Test that registered modules are accessible with valid names."""
        # Get actual registered modules
        registered_modules = ModuleRegistry.list_modules()

        for module_name in registered_modules:
            module_class = ModuleRegistry.get(module_name)
            assert module_class is not None
            assert issubclass(module_class, BaseModule)

    def test_invalid_characters_blocked(self):
        """Test that invalid characters are blocked."""
        invalid_chars = [
            "module@name",
            "module#name",
            "module$name",
            "module%name",
            "module&name",
            "module*name",
            "module(name",
            "module)name",
            "module+name",
            "module=name",
            "module[name",
            "module]name",
            "module{name",
            "module}name",
            "module|name",
            "module:name",
            "module;name",
            'module"name',
            "module'name",
            "module<name",
            "module>name",
            "module?name",
            "module,name",
            "module.name",  # Dots might be allowed, but we restrict for security
        ]

        for invalid_name in invalid_chars:
            with pytest.raises((ValueError, KeyError)):
                # Should fail validation (ValueError) or not be registered (KeyError)
                ModuleRegistry.get(invalid_name)

    def test_none_rejected(self):
        """Test that None is rejected."""
        with pytest.raises(ValueError, match="non-empty string"):
            ModuleRegistry.get(None)

    def test_non_string_rejected(self):
        """Test that non-string types are rejected."""
        invalid_types = [
            123,
            [],
            {},
            True,
        ]

        for invalid_type in invalid_types:
            with pytest.raises(ValueError, match="non-empty string"):
                ModuleRegistry.get(invalid_type)

    def test_register_validates_name(self):
        """Test that register() also validates module names."""

        # Create a dummy module class for testing
        class DummyModule(BaseModule):
            async def process(self, payload, headers):
                pass

        # Valid name should work
        try:
            ModuleRegistry.register("test_module_123", DummyModule)
            # Clean up
            del ModuleRegistry._modules["test_module_123"]
        except ValueError:
            pytest.fail("Valid module name was rejected during registration")

        # Invalid name should be rejected
        with pytest.raises(ValueError):
            ModuleRegistry.register("../malicious", DummyModule)

        # Invalid module class should be rejected
        with pytest.raises(ValueError, match="inherit from BaseModule"):
            ModuleRegistry.register("valid_name", object)

    def test_case_sensitive_lookup(self):
        """Test that module lookup is case-sensitive (security feature)."""
        # 'log' is registered, but 'Log' should not be found
        ModuleRegistry.get("log")  # Should work

        with pytest.raises(KeyError):
            ModuleRegistry.get("Log")  # Should fail (case-sensitive)

        with pytest.raises(KeyError):
            ModuleRegistry.get("LOG")  # Should fail (case-sensitive)
