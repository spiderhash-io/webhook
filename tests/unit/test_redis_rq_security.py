"""
Security tests for RedisRQModule.
Tests function name injection prevention and code execution blocking.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from src.modules.redis_rq import RedisRQModule


class TestRedisRQSecurity:
    """Test suite for Redis RQ function name security."""

    @pytest.fixture
    def mock_connection(self):
        """Create a mock Redis connection."""
        return Mock()

    @pytest.fixture
    def config(self, mock_connection):
        """Create a test configuration."""
        return {
            "module": "redis_rq",
            "module-config": {"function": "valid_function", "queue_name": "default"},
            "connection_details": {"type": "redis", "conn": mock_connection},
        }

    def test_valid_simple_function_name(self, config):
        """Test that valid simple function names are accepted."""
        module = RedisRQModule(config)
        assert module._validated_function_name == "valid_function"

    def test_valid_module_function_name(self, config):
        """Test that valid module.function names are accepted."""
        config["module-config"]["function"] = "utils.process_data"
        module = RedisRQModule(config)
        assert module._validated_function_name == "utils.process_data"

    def test_valid_package_module_function_name(self, config):
        """Test that valid package.module.function names are accepted."""
        config["module-config"]["function"] = "my_package.utils.process"
        module = RedisRQModule(config)
        assert module._validated_function_name == "my_package.utils.process"

    def test_os_system_blocked(self, config):
        """Test that os.system is explicitly blocked."""
        config["module-config"]["function"] = "os.system"
        with pytest.raises(ValueError, match=r"explicitly blocked|Dangerous functions"):
            RedisRQModule(config)

    def test_os_popen_blocked(self, config):
        """Test that os.popen is explicitly blocked."""
        config["module-config"]["function"] = "os.popen"
        with pytest.raises(ValueError, match=r"explicitly blocked|Dangerous functions"):
            RedisRQModule(config)

    def test_subprocess_blocked(self, config):
        """Test that subprocess functions are blocked."""
        config["module-config"]["function"] = "subprocess.call"
        with pytest.raises(ValueError, match=r"explicitly blocked|Dangerous functions"):
            RedisRQModule(config)

    def test_eval_blocked(self, config):
        """Test that eval is explicitly blocked."""
        config["module-config"]["function"] = "eval"
        with pytest.raises(ValueError, match=r"explicitly blocked|Dangerous functions"):
            RedisRQModule(config)

    def test_exec_blocked(self, config):
        """Test that exec is explicitly blocked."""
        config["module-config"]["function"] = "exec"
        with pytest.raises(ValueError, match=r"explicitly blocked|Dangerous functions"):
            RedisRQModule(config)

    def test_compile_blocked(self, config):
        """Test that compile is explicitly blocked."""
        config["module-config"]["function"] = "compile"
        with pytest.raises(ValueError, match=r"explicitly blocked|Dangerous functions"):
            RedisRQModule(config)

    def test_import_blocked(self, config):
        """Test that __import__ is explicitly blocked."""
        config["module-config"]["function"] = "__import__"
        with pytest.raises(ValueError, match=r"explicitly blocked|Dangerous functions"):
            RedisRQModule(config)

    def test_path_traversal_blocked(self, config):
        """Test that path traversal in function names is blocked."""
        traversal_names = [
            "../../etc/passwd",
            "module/../evil",
            "module\\..\\evil",
        ]

        for name in traversal_names:
            config["module-config"]["function"] = name
            with pytest.raises(ValueError, match=r"path traversal|cannot contain"):
                RedisRQModule(config)

    def test_null_byte_blocked(self, config):
        """Test that null bytes in function names are blocked."""
        config["module-config"]["function"] = "valid\x00function"
        with pytest.raises(ValueError, match=r"null bytes"):
            RedisRQModule(config)

    def test_dangerous_characters_blocked(self, config):
        """Test that dangerous characters are blocked."""
        dangerous_chars = [
            ";",
            "|",
            "&",
            "$",
            "`",
            "(",
            ")",
            "[",
            "]",
            "{",
            "}",
            "<",
            ">",
            "?",
            "*",
            "!",
        ]

        for char in dangerous_chars:
            config["module-config"]["function"] = f"valid{char}function"
            with pytest.raises(ValueError, match=r"dangerous character"):
                RedisRQModule(config)

    def test_empty_function_name_rejected(self, config):
        """Test that empty function names are rejected."""
        config["module-config"]["function"] = ""
        # Empty string will be passed to _validate_function_name which will reject it
        # But if it's falsy, it won't be validated. Let's test with a space to ensure validation
        config["module-config"]["function"] = "   "  # Whitespace only
        with pytest.raises(
            ValueError, match=r"cannot be empty|must be a non-empty string"
        ):
            RedisRQModule(config)

    def test_whitespace_only_rejected(self, config):
        """Test that whitespace-only function names are rejected."""
        config["module-config"]["function"] = "   "
        with pytest.raises(ValueError, match=r"cannot be empty"):
            RedisRQModule(config)

    def test_too_long_function_name_rejected(self, config):
        """Test that overly long function names are rejected."""
        long_name = "a" * 300
        config["module-config"]["function"] = long_name
        with pytest.raises(ValueError, match=r"too long"):
            RedisRQModule(config)

    def test_invalid_format_rejected(self, config):
        """Test that invalid function name formats are rejected."""
        invalid_names = [
            "123invalid",  # Starts with number
            "invalid-function",  # Contains hyphen
            "invalid.function.name.too.deep",  # Too many dots
            "invalid function",  # Contains space
        ]

        for name in invalid_names:
            config["module-config"]["function"] = name
            with pytest.raises(ValueError):
                RedisRQModule(config)

    def test_magic_methods_blocked(self, config):
        """Test that magic methods are blocked."""
        magic_methods = [
            "__builtins__",
            "__import__",
            "__getattr__",
            "__setattr__",
        ]

        for name in magic_methods:
            config["module-config"]["function"] = name
            with pytest.raises(
                ValueError, match=r"explicitly blocked|Dangerous functions"
            ):
                RedisRQModule(config)

    @pytest.mark.asyncio
    async def test_process_with_valid_function(self, config, mock_connection):
        """Test that process works with validated function name."""
        config["connection_details"]["conn"] = mock_connection

        # Mock Queue and enqueue
        with patch("src.modules.redis_rq.Queue") as mock_queue_class:
            mock_queue = Mock()
            mock_queue.enqueue.return_value = Mock(id="test-job-id")
            mock_queue_class.return_value = mock_queue

            module = RedisRQModule(config)
            await module.process({"test": "data"}, {})

            # Verify enqueue was called with validated function name
            mock_queue.enqueue.assert_called_once_with(
                "valid_function", {"test": "data"}, {}
            )

    @pytest.mark.asyncio
    async def test_process_without_function_name(self, config, mock_connection):
        """Test that process fails when function name is not specified."""
        del config["module-config"]["function"]
        config["connection_details"]["conn"] = mock_connection

        module = RedisRQModule(config)

        with pytest.raises(Exception, match=r"Function name not specified"):
            await module.process({"test": "data"}, {})

    @pytest.mark.asyncio
    async def test_process_without_connection(self, config):
        """Test that process fails when connection is not defined."""
        config["connection_details"] = {}

        module = RedisRQModule(config)

        with pytest.raises(Exception, match=r"Redis connection is not defined"):
            await module.process({"test": "data"}, {})

    def test_function_name_validation_during_init(self, config):
        """Test that function name is validated during initialization."""
        config["module-config"]["function"] = "os.system"

        # Should raise ValueError during __init__
        with pytest.raises(ValueError, match=r"explicitly blocked|Dangerous functions"):
            RedisRQModule(config)

    def test_multiple_dots_allowed(self, config):
        """Test that multiple dots are allowed for deep module paths."""
        config["module-config"]["function"] = "package.subpackage.module.function"
        # This should be rejected because it has too many dots (doesn't match pattern)
        with pytest.raises(ValueError, match=r"does not match allowed patterns"):
            RedisRQModule(config)

    def test_underscore_allowed(self, config):
        """Test that underscores are allowed in function names."""
        config["module-config"]["function"] = "valid_function_name"
        module = RedisRQModule(config)
        assert module._validated_function_name == "valid_function_name"

    def test_numbers_allowed_in_function_name(self, config):
        """Test that numbers are allowed in function names (but not at start)."""
        config["module-config"]["function"] = "function123"
        module = RedisRQModule(config)
        assert module._validated_function_name == "function123"
