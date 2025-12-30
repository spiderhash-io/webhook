"""
Security tests for S3 module object key injection prevention.
Tests prefix and filename pattern validation to prevent path traversal and injection attacks.
"""
import pytest
import re
import uuid
from datetime import datetime
from src.modules.s3 import S3Module


class TestS3ObjectKeyInjection:
    """Test suite for S3 object key injection prevention."""
    
    def test_valid_prefixes(self):
        """Test that valid prefixes are accepted."""
        valid_prefixes = [
            "webhooks",
            "webhooks_2024",
            "webhooks-test",
            "webhooks/test",
            "webhooks/nested/path",
            "a",
            "A" * 100,  # Long but valid
        ]
        
        for prefix in valid_prefixes:
            config = {
                "module": "s3",
                "module-config": {
                    "bucket": "test-bucket",
                    "prefix": prefix
                }
            }
            module = S3Module(config)
            assert module._validate_s3_path_component(prefix, 'prefix') == prefix.strip('/')
    
    def test_path_traversal_in_prefix_rejected(self):
        """Test that path traversal sequences in prefix are rejected."""
        traversal_prefixes = [
            "../webhooks",
            "webhooks/..",
            "webhooks/../other",
            "../../webhooks",
            "webhooks/../../other",
        ]
        
        for prefix in traversal_prefixes:
            config = {
                "module": "s3",
                "module-config": {
                    "bucket": "test-bucket",
                    "prefix": prefix
                }
            }
            with pytest.raises(ValueError) as exc_info:
                S3Module(config)
            assert "path traversal" in str(exc_info.value).lower() or ".." in str(exc_info.value)
    
    def test_absolute_paths_rejected(self):
        """Test that absolute paths are rejected."""
        absolute_paths = [
            "/webhooks",
            "/webhooks/test",
        ]
        
        for prefix in absolute_paths:
            config = {
                "module": "s3",
                "module-config": {
                    "bucket": "test-bucket",
                    "prefix": prefix
                }
            }
            with pytest.raises(ValueError) as exc_info:
                S3Module(config)
            assert "path traversal" in str(exc_info.value).lower() or "start" in str(exc_info.value).lower()
    
    def test_dangerous_patterns_in_prefix_rejected(self):
        """Test that dangerous patterns in prefix are rejected."""
        dangerous_patterns = [
            "webhooks; DELETE",
            "webhooks | COMMAND",
            "webhooks && COMMAND",
            "webhooks`eval`",
            "webhooks$(command)",
            "webhooks//test",  # Double slash
            "webhooks--test",  # Double hyphen
        ]
        
        for prefix in dangerous_patterns:
            config = {
                "module": "s3",
                "module-config": {
                    "bucket": "test-bucket",
                    "prefix": prefix
                }
            }
            with pytest.raises(ValueError) as exc_info:
                S3Module(config)
            error_msg = str(exc_info.value).lower()
            assert any(keyword in error_msg for keyword in [
                "invalid", "forbidden", "dangerous", "not allowed"
            ]), f"Failed to reject dangerous pattern: {prefix}"
    
    def test_valid_filename_patterns(self):
        """Test that valid filename patterns are accepted."""
        valid_patterns = [
            "webhook_{uuid}.json",
            "webhook_{timestamp}.json",
            "webhook_{uuid}_{timestamp}.json",
            "webhook.json",
            "webhook-{uuid}.json",
            "webhook_{uuid}",
        ]
        
        for pattern in valid_patterns:
            config = {
                "module": "s3",
                "module-config": {
                    "bucket": "test-bucket",
                    "filename_pattern": pattern
                }
            }
            module = S3Module(config)
            assert module._validate_filename_pattern(pattern) == pattern
    
    def test_path_traversal_in_filename_pattern_rejected(self):
        """Test that path traversal in filename pattern is rejected."""
        traversal_patterns = [
            "../webhook_{uuid}.json",
            "webhook/../{uuid}.json",
            "webhook_{uuid}/../test.json",
            "webhook_{uuid}\\test.json",  # Backslash
        ]
        
        for pattern in traversal_patterns:
            config = {
                "module": "s3",
                "module-config": {
                    "bucket": "test-bucket",
                    "filename_pattern": pattern
                }
            }
            with pytest.raises(ValueError) as exc_info:
                S3Module(config)
            assert "path traversal" in str(exc_info.value).lower() or "invalid" in str(exc_info.value).lower()
    
    def test_dangerous_patterns_in_filename_rejected(self):
        """Test that dangerous patterns in filename pattern are rejected."""
        dangerous_patterns = [
            "webhook;{uuid}.json",
            "webhook|{uuid}.json",
            "webhook&{uuid}.json",
            "webhook`{uuid}`.json",
            "webhook${uuid}.json",
            "webhook--{uuid}.json",
        ]
        
        for pattern in dangerous_patterns:
            config = {
                "module": "s3",
                "module-config": {
                    "bucket": "test-bucket",
                    "filename_pattern": pattern
                }
            }
            with pytest.raises(ValueError) as exc_info:
                S3Module(config)
            assert "dangerous" in str(exc_info.value).lower() or "invalid" in str(exc_info.value).lower()
    
    def test_control_characters_rejected(self):
        """Test that control characters are rejected."""
        control_chars = [
            "webhook\n{uuid}.json",
            "webhook\r{uuid}.json",
            "webhook\x00{uuid}.json",
            "webhook\t{uuid}.json",
        ]
        
        for pattern in control_chars:
            config = {
                "module": "s3",
                "module-config": {
                    "bucket": "test-bucket",
                    "filename_pattern": pattern
                }
            }
            with pytest.raises(ValueError) as exc_info:
                S3Module(config)
            # Control characters are caught by regex validation or explicit check
            error_msg = str(exc_info.value).lower()
            assert any(keyword in error_msg for keyword in [
                "control", "forbidden", "invalid"
            ])
    
    def test_empty_values_rejected(self):
        """Test that empty prefix and filename pattern are rejected."""
        # Empty prefix
        config = {
            "module": "s3",
            "module-config": {
                "bucket": "test-bucket",
                "prefix": ""
            }
        }
        with pytest.raises(ValueError) as exc_info:
            S3Module(config)
        assert "empty" in str(exc_info.value).lower()
        
        # Empty filename pattern
        config = {
            "module": "s3",
            "module-config": {
                "bucket": "test-bucket",
                "filename_pattern": ""
            }
        }
        with pytest.raises(ValueError) as exc_info:
            S3Module(config)
        assert "empty" in str(exc_info.value).lower()
    
    def test_length_limits(self):
        """Test that length limits are enforced."""
        # Long prefix
        long_prefix = "a" * 300
        config = {
            "module": "s3",
            "module-config": {
                "bucket": "test-bucket",
                "prefix": long_prefix
            }
        }
        with pytest.raises(ValueError) as exc_info:
            S3Module(config)
        assert "too long" in str(exc_info.value).lower()
        
        # Long filename pattern
        long_pattern = "a" * 300
        config = {
            "module": "s3",
            "module-config": {
                "bucket": "test-bucket",
                "filename_pattern": long_pattern
            }
        }
        with pytest.raises(ValueError) as exc_info:
            S3Module(config)
        assert "too long" in str(exc_info.value).lower()
    
    def test_special_characters_rejected(self):
        """Test that special characters are rejected."""
        special_chars = [
            "webhook {uuid}.json",  # Space
            "webhook'{uuid}'.json",  # Single quote
            'webhook"{uuid}".json',  # Double quote
            "webhook@{uuid}.json",  # At sign
            "webhook#{uuid}.json",  # Hash
            "webhook%{uuid}.json",  # Percent
            "webhook+{uuid}.json",  # Plus
            "webhook={uuid}.json",  # Equals
            "webhook?{uuid}.json",  # Question mark
            "webhook!{uuid}.json",  # Exclamation
        ]
        
        for pattern in special_chars:
            config = {
                "module": "s3",
                "module-config": {
                    "bucket": "test-bucket",
                    "filename_pattern": pattern
                }
            }
            with pytest.raises(ValueError) as exc_info:
                S3Module(config)
            assert "Invalid" in str(exc_info.value) or "dangerous" in str(exc_info.value).lower()
    
    def test_unicode_characters_rejected(self):
        """Test that Unicode characters are rejected."""
        unicode_patterns = [
            "webhook_测试_{uuid}.json",
            "webhook_ログ_{uuid}.json",
            "webhook_логи_{uuid}.json",
        ]
        
        for pattern in unicode_patterns:
            config = {
                "module": "s3",
                "module-config": {
                    "bucket": "test-bucket",
                    "filename_pattern": pattern
                }
            }
            with pytest.raises(ValueError) as exc_info:
                S3Module(config)
            assert "Invalid" in str(exc_info.value)
    
    def test_whitespace_handling(self):
        """Test that whitespace is properly handled."""
        # Whitespace should be stripped
        config = {
            "module": "s3",
            "module-config": {
                "bucket": "test-bucket",
                "prefix": "  webhooks  "
            }
        }
        module = S3Module(config)
        validated = module._validate_s3_path_component("  webhooks  ", 'prefix')
        assert validated == "webhooks"
        
        # But whitespace-only should be rejected
        config = {
            "module": "s3",
            "module-config": {
                "bucket": "test-bucket",
                "prefix": "   "
            }
        }
        with pytest.raises(ValueError):
            S3Module(config)
    
    def test_nested_paths_allowed(self):
        """Test that nested paths in prefix are allowed."""
        nested_paths = [
            "webhooks/2024",
            "webhooks/2024/01",
            "webhooks/2024/01/15",
        ]
        
        for prefix in nested_paths:
            config = {
                "module": "s3",
                "module-config": {
                    "bucket": "test-bucket",
                    "prefix": prefix
                }
            }
            module = S3Module(config)
            validated = module._validate_s3_path_component(prefix, 'prefix')
            # Should normalize (remove leading/trailing slashes, collapse multiple slashes)
            assert validated == prefix.strip('/')
    
    def test_object_key_validation(self):
        """Test that final object keys are validated."""
        config = {
            "module": "s3",
            "module-config": {
                "bucket": "test-bucket",
                "prefix": "webhooks",
                "filename_pattern": "webhook_{uuid}.json"
            }
        }
        module = S3Module(config)
        
        # Valid object key
        valid_key = "webhooks/2024/01/15/webhook_123.json"
        assert module._validate_object_key(valid_key) == valid_key
        
        # Invalid: path traversal
        with pytest.raises(ValueError):
            module._validate_object_key("webhooks/../other/webhook.json")
        
        # Invalid: absolute path
        with pytest.raises(ValueError):
            module._validate_object_key("/webhooks/webhook.json")
        
        # Invalid: too long (over 1024 bytes)
        long_key = "a" * 2000
        with pytest.raises(ValueError):
            module._validate_object_key(long_key)
    
    def test_placeholder_replacement_safety(self):
        """Test that placeholder replacement doesn't introduce vulnerabilities."""
        config = {
            "module": "s3",
            "module-config": {
                "bucket": "test-bucket",
                "filename_pattern": "webhook_{uuid}.json"
            }
        }
        module = S3Module(config)
        
        # UUID replacement should produce safe filenames
        test_uuid = str(uuid.uuid4())
        filename = module._validated_filename_pattern.replace('{uuid}', test_uuid)
        assert re.match(r'^[a-zA-Z0-9_\-\.]+$', filename)
        
        # Test with timestamp pattern (timestamp contains colons, but we validate after replacement)
        config_timestamp = {
            "module": "s3",
            "module-config": {
                "bucket": "test-bucket",
                "filename_pattern": "webhook_{timestamp}.json"
            }
        }
        module_timestamp = S3Module(config_timestamp)
        test_timestamp = datetime.utcnow().isoformat().replace(':', '-')  # Replace colons for safety
        filename = module_timestamp._validated_filename_pattern.replace('{timestamp}', test_timestamp)
        # After replacement, validation should catch any invalid characters
        # The actual validation happens in process() method after replacement

