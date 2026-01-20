"""
Tests for environment variable loading functionality.
"""

import pytest
import os
from src.utils import load_env_vars


def test_load_env_vars_simple_replacement():
    """Test simple environment variable replacement."""
    os.environ["TEST_VAR"] = "test_value"

    config = {"key": "{$TEST_VAR}"}

    result = load_env_vars(config)
    assert result["key"] == "test_value"


def test_load_env_vars_with_default():
    """Test environment variable with default value."""
    # Variable not set, should use default
    if "TEST_VAR_DEFAULT" in os.environ:
        del os.environ["TEST_VAR_DEFAULT"]

    config = {"key": "{$TEST_VAR_DEFAULT:default_value}"}

    result = load_env_vars(config)
    assert result["key"] == "default_value"

    # Variable set, should use env var
    os.environ["TEST_VAR_DEFAULT"] = "env_value"
    config = {"key": "{$TEST_VAR_DEFAULT:default_value}"}

    result = load_env_vars(config)
    assert result["key"] == "env_value"


def test_load_env_vars_embedded_in_string():
    """Test environment variables embedded in strings."""
    os.environ["HOST"] = "api.example.com"
    os.environ["PORT"] = "8080"

    config = {"url": "http://{$HOST}:{$PORT}/api"}

    result = load_env_vars(config)
    assert result["url"] == "http://api.example.com:8080/api"


def test_load_env_vars_embedded_with_defaults():
    """Test embedded environment variables with default values."""
    # Clear env vars
    if "HOST" in os.environ:
        del os.environ["HOST"]
    if "PORT" in os.environ:
        del os.environ["PORT"]

    config = {"url": "http://{$HOST:localhost}:{$PORT:3000}/api"}

    result = load_env_vars(config)
    assert result["url"] == "http://localhost:3000/api"

    # Set one var, use default for other
    os.environ["HOST"] = "custom.host"
    config = {"url": "http://{$HOST:localhost}:{$PORT:3000}/api"}

    result = load_env_vars(config)
    assert result["url"] == "http://custom.host:3000/api"


def test_load_env_vars_nested_dict():
    """Test environment variables in nested dictionaries."""
    os.environ["DB_HOST"] = "db.example.com"
    os.environ["DB_PORT"] = "5432"

    config = {
        "database": {"host": "{$DB_HOST}", "port": "{$DB_PORT:5432}", "name": "mydb"}
    }

    result = load_env_vars(config)
    assert result["database"]["host"] == "db.example.com"
    assert result["database"]["port"] == "5432"
    assert result["database"]["name"] == "mydb"


def test_load_env_vars_in_list():
    """Test environment variables in lists."""
    os.environ["ITEM1"] = "value1"
    os.environ["ITEM2"] = "value2"

    config = {"items": ["{$ITEM1}", "{$ITEM2:default2}", "static_value"]}

    result = load_env_vars(config)
    assert result["items"][0] == "value1"
    assert result["items"][1] == "value2"
    assert result["items"][2] == "static_value"


def test_load_env_vars_missing_without_default():
    """Test missing environment variable without default."""
    if "MISSING_VAR" in os.environ:
        del os.environ["MISSING_VAR"]

    config = {"key": "{$MISSING_VAR}"}

    result = load_env_vars(config)
    # Should have warning message
    assert "Undefined variable" in result["key"] or "MISSING_VAR" in result["key"]


def test_load_env_vars_mixed_types():
    """Test environment variables with mixed types."""
    os.environ["STRING_VAR"] = "string_value"
    os.environ["NUM_VAR"] = "12345"

    config = {
        "string_field": "{$STRING_VAR}",
        "number_field": "{$NUM_VAR:0}",
        "boolean_field": True,
        "null_field": None,
    }

    result = load_env_vars(config)
    assert result["string_field"] == "string_value"
    assert result["number_field"] == "12345"
    assert result["boolean_field"] is True
    assert result["null_field"] is None


def test_load_env_vars_complex_nested():
    """Test complex nested structure with environment variables."""
    os.environ["API_HOST"] = "api.prod.com"
    os.environ["API_KEY"] = "secret_key_123"

    config = {
        "webhook": {
            "module": "http_webhook",
            "module-config": {
                "url": "https://{$API_HOST}/webhooks",
                "headers": {
                    "Authorization": "Bearer {$API_KEY}",
                    "X-Custom": "{$CUSTOM_HEADER:default_header}",
                },
            },
            "retry": {"enabled": True, "max_attempts": "{$MAX_RETRIES:3}"},
        }
    }

    result = load_env_vars(config)
    assert result["webhook"]["module-config"]["url"] == "https://api.prod.com/webhooks"
    assert (
        result["webhook"]["module-config"]["headers"]["Authorization"]
        == "Bearer secret_key_123"
    )
    assert result["webhook"]["module-config"]["headers"]["X-Custom"] == "default_header"
    assert result["webhook"]["retry"]["max_attempts"] == "3"


def test_load_env_vars_empty_string_default():
    """Test default value as empty string."""
    if "EMPTY_VAR" in os.environ:
        del os.environ["EMPTY_VAR"]

    config = {"password": "{$EMPTY_VAR:}"}

    result = load_env_vars(config)
    assert result["password"] == ""


def test_load_env_vars_multiple_in_same_string():
    """Test multiple environment variables in the same string."""
    os.environ["PROTOCOL"] = "https"
    os.environ["DOMAIN"] = "example.com"
    os.environ["PATH"] = "api/v1"

    config = {"url": "{$PROTOCOL}://{$DOMAIN}/{$PATH}/webhook"}

    result = load_env_vars(config)
    assert result["url"] == "https://example.com/api/v1/webhook"


def test_load_env_vars_no_replacement_needed():
    """Test that strings without variables are not modified."""
    config = {"normal_string": "no variables here", "number": 123, "boolean": True}

    result = load_env_vars(config)
    assert result["normal_string"] == "no variables here"
    assert result["number"] == 123
    assert result["boolean"] is True
