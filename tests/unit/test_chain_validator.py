"""
Unit tests for chain validator.
"""

import pytest
from src.chain_validator import ChainValidator
from src.modules.registry import ModuleRegistry


class TestChainValidator:
    """Test chain configuration validation."""

    def test_validate_chain_config_no_chain(self):
        """Test validation when chain is not present (backward compatibility)."""
        config = {"module": "log", "data_type": "json"}
        is_valid, error = ChainValidator.validate_chain_config(config)
        assert is_valid is True
        assert error is None

    def test_validate_chain_config_simple_array(self):
        """Test validation with simple array format."""
        config = {
            "chain": ["log", "save_to_disk"],
            "chain-config": {"execution": "sequential", "continue_on_error": True},
        }
        is_valid, error = ChainValidator.validate_chain_config(config)
        assert is_valid is True
        assert error is None

    def test_validate_chain_config_detailed_format(self):
        """Test validation with detailed format."""
        config = {
            "chain": [
                {
                    "module": "log",
                    "connection": "local",
                    "module-config": {"level": "info"},
                },
                {
                    "module": "save_to_disk",
                    "retry": {"enabled": True, "max_attempts": 3},
                },
            ],
            "chain-config": {"execution": "parallel", "continue_on_error": False},
        }
        is_valid, error = ChainValidator.validate_chain_config(config)
        assert is_valid is True
        assert error is None

    def test_validate_chain_config_empty_chain(self):
        """Test validation with empty chain."""
        config = {"chain": []}
        is_valid, error = ChainValidator.validate_chain_config(config)
        assert is_valid is False
        assert "at least" in error.lower()

    def test_validate_chain_config_too_long(self):
        """Test validation with chain exceeding security limit."""
        # Create a chain with 21 modules (exceeds MAX_CHAIN_LENGTH of 20)
        long_chain = ["log"] * 21
        config = {"chain": long_chain}
        is_valid, error = ChainValidator.validate_chain_config(config)
        assert is_valid is False
        assert "exceeds security limit" in error.lower()

    def test_validate_chain_config_not_list(self):
        """Test validation when chain is not a list."""
        config = {"chain": "not_a_list"}
        is_valid, error = ChainValidator.validate_chain_config(config)
        assert is_valid is False
        assert "must be a list" in error.lower()

    def test_validate_chain_config_invalid_module(self):
        """Test validation with invalid module name."""
        config = {"chain": ["nonexistent_module"]}
        is_valid, error = ChainValidator.validate_chain_config(config)
        assert is_valid is False
        assert "not registered" in error.lower()

    def test_validate_chain_config_invalid_execution_mode(self):
        """Test validation with invalid execution mode."""
        config = {"chain": ["log"], "chain-config": {"execution": "invalid_mode"}}
        is_valid, error = ChainValidator.validate_chain_config(config)
        assert is_valid is False
        assert "execution" in error.lower()

    def test_validate_chain_config_invalid_continue_on_error(self):
        """Test validation with invalid continue_on_error type."""
        config = {
            "chain": ["log"],
            "chain-config": {
                "execution": "sequential",
                "continue_on_error": "not_a_boolean",
            },
        }
        is_valid, error = ChainValidator.validate_chain_config(config)
        assert is_valid is False
        assert "boolean" in error.lower()

    def test_validate_chain_item_string_format(self):
        """Test validation of string format chain item."""
        is_valid, error = ChainValidator._validate_chain_item("log", 0)
        assert is_valid is True
        assert error is None

    def test_validate_chain_item_dict_format(self):
        """Test validation of dict format chain item."""
        item = {
            "module": "log",
            "connection": "local",
            "module-config": {"level": "info"},
            "retry": {"enabled": True, "max_attempts": 3},
        }
        is_valid, error = ChainValidator._validate_chain_item(item, 0)
        assert is_valid is True
        assert error is None

    def test_validate_chain_item_missing_module(self):
        """Test validation of chain item missing module field."""
        item = {"connection": "local"}
        is_valid, error = ChainValidator._validate_chain_item(item, 0)
        assert is_valid is False
        assert "module" in error.lower()

    def test_validate_chain_item_invalid_module_type(self):
        """Test validation of chain item with invalid module type."""
        item = {"module": 123}  # Should be string
        is_valid, error = ChainValidator._validate_chain_item(item, 0)
        assert is_valid is False
        assert "string" in error.lower()

    def test_validate_chain_item_invalid_connection_type(self):
        """Test validation of chain item with invalid connection type."""
        item = {"module": "log", "connection": 123}  # Should be string
        is_valid, error = ChainValidator._validate_chain_item(item, 0)
        assert is_valid is False
        assert "string" in error.lower()

    def test_validate_chain_item_invalid_module_config_type(self):
        """Test validation of chain item with invalid module-config type."""
        item = {"module": "log", "module-config": "not_a_dict"}  # Should be dict
        is_valid, error = ChainValidator._validate_chain_item(item, 0)
        assert is_valid is False
        assert "dictionary" in error.lower()

    def test_validate_chain_item_invalid_retry_type(self):
        """Test validation of chain item with invalid retry type."""
        item = {"module": "log", "retry": "not_a_dict"}  # Should be dict
        is_valid, error = ChainValidator._validate_chain_item(item, 0)
        assert is_valid is False
        assert "dictionary" in error.lower()

    def test_validate_chain_item_invalid_retry_max_attempts(self):
        """Test validation of chain item with invalid retry max_attempts."""
        item = {
            "module": "log",
            "retry": {"enabled": True, "max_attempts": -1},  # Should be positive
        }
        is_valid, error = ChainValidator._validate_chain_item(item, 0)
        assert is_valid is False
        assert "positive integer" in error.lower()

    def test_validate_chain_item_unknown_field(self):
        """Test validation of chain item with unknown field."""
        item = {"module": "log", "unknown_field": "value"}
        is_valid, error = ChainValidator._validate_chain_item(item, 0)
        assert is_valid is False
        assert "unknown field" in error.lower()

    def test_validate_chain_item_invalid_type(self):
        """Test validation of chain item with invalid type."""
        is_valid, error = ChainValidator._validate_chain_item(123, 0)
        assert is_valid is False
        assert "string or dictionary" in error.lower()

    def test_normalize_chain_item_string(self):
        """Test normalization of string chain item."""
        normalized = ChainValidator.normalize_chain_item("log")
        assert normalized == {"module": "log"}

    def test_normalize_chain_item_dict(self):
        """Test normalization of dict chain item."""
        item = {"module": "log", "connection": "local"}
        normalized = ChainValidator.normalize_chain_item(item)
        assert normalized == item

    def test_get_chain_modules(self):
        """Test extraction of module names from chain."""
        chain = ["log", {"module": "save_to_disk", "connection": "local"}]
        modules = ChainValidator.get_chain_modules(chain)
        assert modules == ["log", "save_to_disk"]

    def test_validate_chain_execution_config_valid(self):
        """Test validation of valid chain execution config."""
        chain_config = {"execution": "sequential", "continue_on_error": True}
        is_valid, error = ChainValidator._validate_chain_execution_config(chain_config)
        assert is_valid is True
        assert error is None

    def test_validate_chain_execution_config_invalid_type(self):
        """Test validation of chain execution config with invalid type."""
        is_valid, error = ChainValidator._validate_chain_execution_config("not_a_dict")
        assert is_valid is False
        assert "dictionary" in error.lower()

    def test_validate_chain_execution_config_unknown_field(self):
        """Test validation of chain execution config with unknown field."""
        chain_config = {"execution": "sequential", "unknown_field": "value"}
        is_valid, error = ChainValidator._validate_chain_execution_config(chain_config)
        assert is_valid is False
        assert "unknown field" in error.lower()
