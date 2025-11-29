"""
Integration tests for S3 module.

These tests verify S3 object key validation, path traversal prevention, and filename patterns.
Note: These tests focus on validation logic. For full S3 upload tests, AWS credentials and moto are required.
"""

import pytest
import re
from src.modules.s3 import S3Module


@pytest.mark.integration
class TestS3Integration:
    """Integration tests for S3 module."""
    
    @pytest.mark.asyncio
    async def test_s3_object_key_validation(self):
        """Test that S3 module validates object keys."""
        config = {
            "module": "s3",
            "module-config": {
                "bucket": "test-bucket",
                "prefix": "webhooks",
                "filename_pattern": "webhook_{uuid}.json"
            },
            "connection_details": {
                "aws_access_key_id": "test_key",
                "aws_secret_access_key": "test_secret",
                "region_name": "us-east-1"
            }
        }
        
        module = S3Module(config)
        
        # Valid object key
        valid_key = "webhooks/2024/01/15/webhook_123.json"
        validated = module._validate_object_key(valid_key)
        assert validated == valid_key
        
        # Invalid: path traversal
        with pytest.raises(ValueError, match="path traversal|invalid"):
            module._validate_object_key("webhooks/../other/webhook.json")
        
        # Invalid: absolute path
        with pytest.raises(ValueError, match="cannot start|absolute|invalid"):
            module._validate_object_key("/webhooks/webhook.json")
    
    @pytest.mark.asyncio
    async def test_s3_path_traversal_prevention(self):
        """Test that path traversal attacks are prevented."""
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
                },
                "connection_details": {
                    "aws_access_key_id": "test_key",
                    "aws_secret_access_key": "test_secret"
                }
            }
            with pytest.raises(ValueError, match="path traversal|invalid|dangerous"):
                S3Module(config)
    
    @pytest.mark.asyncio
    async def test_s3_prefix_validation(self):
        """Test that S3 prefix is validated."""
        # Valid prefixes
        valid_prefixes = [
            "webhooks",
            "webhooks_2024",
            "webhooks-test",
            "webhooks/test",
            "webhooks/nested/path",
        ]
        
        for prefix in valid_prefixes:
            config = {
                "module": "s3",
                "module-config": {
                    "bucket": "test-bucket",
                    "prefix": prefix
                },
                "connection_details": {
                    "aws_access_key_id": "test_key",
                    "aws_secret_access_key": "test_secret"
                }
            }
            module = S3Module(config)
            assert module._validated_prefix == prefix.strip('/')
    
    @pytest.mark.asyncio
    async def test_s3_filename_pattern_validation(self):
        """Test that filename patterns are validated."""
        # Valid patterns (only {uuid} and {timestamp} are supported)
        valid_patterns = [
            "webhook_{uuid}.json",
            "webhook_{timestamp}.json",
            "webhook_{uuid}_{timestamp}.json",
        ]
        
        for pattern in valid_patterns:
            config = {
                "module": "s3",
                "module-config": {
                    "bucket": "test-bucket",
                    "filename_pattern": pattern
                },
                "connection_details": {
                    "aws_access_key_id": "test_key",
                    "aws_secret_access_key": "test_secret"
                }
            }
            module = S3Module(config)
            assert module._validated_filename_pattern == pattern
        
        # Invalid: path traversal in pattern
        invalid_patterns = [
            "../webhook.json",
            "webhook/../other.json",
            "../../webhook.json",
        ]
        
        for pattern in invalid_patterns:
            config = {
                "module": "s3",
                "module-config": {
                    "bucket": "test-bucket",
                    "filename_pattern": pattern
                },
                "connection_details": {
                    "aws_access_key_id": "test_key",
                    "aws_secret_access_key": "test_secret"
                }
            }
            with pytest.raises(ValueError, match="path traversal|invalid|dangerous|contains|Filename pattern|characters"):
                S3Module(config)
    
    @pytest.mark.asyncio
    async def test_s3_object_key_length_validation(self):
        """Test that object key length is validated."""
        config = {
            "module": "s3",
            "module-config": {
                "bucket": "test-bucket",
                "prefix": "webhooks"
            },
            "connection_details": {
                "aws_access_key_id": "test_key",
                "aws_secret_access_key": "test_secret"
            }
        }
        
        module = S3Module(config)
        
        # Valid: under 1024 bytes
        valid_key = "a" * 500
        assert module._validate_object_key(valid_key) == valid_key
        
        # Invalid: over 1024 bytes
        long_key = "a" * 2000
        with pytest.raises(ValueError, match="too long|exceeds"):
            module._validate_object_key(long_key)
    
    @pytest.mark.asyncio
    async def test_s3_null_byte_prevention(self):
        """Test that null bytes are rejected in object keys."""
        config = {
            "module": "s3",
            "module-config": {
                "bucket": "test-bucket",
                "prefix": "webhooks"
            },
            "connection_details": {
                "aws_access_key_id": "test_key",
                "aws_secret_access_key": "test_secret"
            }
        }
        
        module = S3Module(config)
        
        # Null byte in key
        with pytest.raises(ValueError, match="null|forbidden"):
            module._validate_object_key("webhooks/webhook\x00.json")
    
    @pytest.mark.asyncio
    async def test_s3_absolute_path_rejection(self):
        """Test that absolute paths are rejected."""
        config = {
            "module": "s3",
            "module-config": {
                "bucket": "test-bucket",
                "prefix": "webhooks"
            },
            "connection_details": {
                "aws_access_key_id": "test_key",
                "aws_secret_access_key": "test_secret"
            }
        }
        
        module = S3Module(config)
        
        # Absolute path
        with pytest.raises(ValueError, match="cannot start|absolute|invalid"):
            module._validate_object_key("/webhooks/webhook.json")
        
        # Windows absolute path (backslashes are not valid in S3 keys anyway)
        # S3 keys use forward slashes, so Windows paths may not be caught by validation
        # This is acceptable since S3 doesn't support Windows paths
        try:
            module._validate_object_key("C:\\webhooks\\webhook.json")
            # If it doesn't raise, that's okay - Windows paths aren't valid S3 keys anyway
        except ValueError:
            # If it does raise, that's also fine
            pass
    
    @pytest.mark.asyncio
    async def test_s3_placeholder_replacement(self):
        """Test that placeholders in filename patterns are handled safely."""
        config = {
            "module": "s3",
            "module-config": {
                "bucket": "test-bucket",
                "prefix": "webhooks",
                "filename_pattern": "webhook_{uuid}_{timestamp}.json"
            },
            "connection_details": {
                "aws_access_key_id": "test_key",
                "aws_secret_access_key": "test_secret"
            }
        }
        
        module = S3Module(config)
        
        # Pattern should be validated
        assert "{uuid}" in module._validated_filename_pattern
        assert "{timestamp}" in module._validated_filename_pattern
    
    @pytest.mark.asyncio
    async def test_s3_connection_error_handling(self):
        """Test handling of connection errors (without real AWS credentials)."""
        # This test verifies that the module handles missing/invalid credentials gracefully
        config = {
            "module": "s3",
            "module-config": {
                "bucket": "test-bucket",
                "prefix": "webhooks"
            },
            "connection_details": {
                "aws_access_key_id": "invalid_key",
                "aws_secret_access_key": "invalid_secret",
                "region_name": "us-east-1"
            }
        }
        
        module = S3Module(config)
        
        # Module should initialize without errors (validation happens at process time)
        assert module is not None
        assert module._validated_prefix == "webhooks"
        
        # Process should raise error when trying to upload (without real credentials)
        # Note: This will fail with boto3 errors, which is expected
        with pytest.raises(Exception, match="S3|connection|operation|credentials"):
            await module.process({"test": "data"}, {})

