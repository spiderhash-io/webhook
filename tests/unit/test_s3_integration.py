"""
Integration tests for s3.py module.
Tests cover missing coverage areas including S3 client initialization, upload logic, and error handling.
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from botocore.exceptions import ClientError

from src.modules.s3 import S3Module


class TestS3ModuleSetup:
    """Test S3 client setup and initialization."""
    
    @pytest.mark.asyncio
    async def test_setup_with_credentials(self):
        """Test setup with AWS credentials."""
        config = {
            'module-config': {
                'bucket': 'test-bucket',
                'prefix': 'webhooks',
                'filename_pattern': 'webhook-{uuid}.json'
            },
            'connection_details': {
                'aws_access_key_id': 'test-key',
                'aws_secret_access_key': 'test-secret',
                'region': 'us-east-1'
            }
        }
        
        module = S3Module(config)
        
        with patch('src.modules.s3.boto3') as mock_boto3:
            mock_client = Mock()
            mock_boto3.client.return_value = mock_client
            
            await module.setup()
            
            mock_boto3.client.assert_called_once_with(
                's3',
                aws_access_key_id='test-key',
                aws_secret_access_key='test-secret',
                region_name='us-east-1'
            )
            assert module.s3_client == mock_client
    
    @pytest.mark.asyncio
    async def test_setup_without_credentials(self):
        """Test setup without explicit credentials (uses IAM role)."""
        config = {
            'module-config': {
                'bucket': 'test-bucket',
                'prefix': 'webhooks',
                'filename_pattern': 'webhook-{uuid}.json'
            },
            'connection_details': {
                'region': 'us-east-1'
            }
        }
        
        module = S3Module(config)
        
        with patch('src.modules.s3.boto3') as mock_boto3:
            mock_client = Mock()
            mock_boto3.client.return_value = mock_client
            
            await module.setup()
            
            mock_boto3.client.assert_called_once_with(
                's3',
                region_name='us-east-1'
            )
            assert module.s3_client == mock_client


class TestS3ModuleProcess:
    """Test S3 upload process method."""
    
    @pytest.mark.asyncio
    async def test_process_with_dict_payload(self):
        """Test processing with dictionary payload."""
        config = {
            'module-config': {
                'bucket': 'test-bucket',
                'prefix': 'webhooks',
                'filename_pattern': 'webhook-{uuid}.json',
                'content_type': 'application/json'
            },
            'connection_details': {
                'aws_access_key_id': 'test-key',
                'aws_secret_access_key': 'test-secret',
                'region': 'us-east-1'
            }
        }
        
        module = S3Module(config)
        
        mock_client = Mock()
        mock_client.put_object = Mock()
        module.s3_client = mock_client
        
        payload = {'key': 'value', 'number': 123}
        headers = {'Content-Type': 'application/json'}
        
        await module.process(payload, headers)
        
        mock_client.put_object.assert_called_once()
        call_kwargs = mock_client.put_object.call_args[1]
        assert call_kwargs['Bucket'] == 'test-bucket'
        assert call_kwargs['ContentType'] == 'application/json'
        assert 'Key' in call_kwargs
    
    @pytest.mark.asyncio
    async def test_process_with_string_payload(self):
        """Test processing with string payload."""
        config = {
            'module-config': {
                'bucket': 'test-bucket',
                'prefix': 'webhooks',
                'filename_pattern': 'webhook-{uuid}.txt'
            },
            'connection_details': {
                'aws_access_key_id': 'test-key',
                'aws_secret_access_key': 'test-secret',
                'region': 'us-east-1'
            }
        }
        
        module = S3Module(config)
        
        mock_client = Mock()
        mock_client.put_object = Mock()
        module.s3_client = mock_client
        
        payload = "Simple string payload"
        headers = {}
        
        await module.process(payload, headers)
        
        mock_client.put_object.assert_called_once()
        call_kwargs = mock_client.put_object.call_args[1]
        assert isinstance(call_kwargs['Body'], bytes)
    
    @pytest.mark.asyncio
    async def test_process_with_headers_metadata(self):
        """Test processing with headers included as metadata."""
        config = {
            'module-config': {
                'bucket': 'test-bucket',
                'prefix': 'webhooks',
                'filename_pattern': 'webhook-{uuid}.json',
                'include_headers': True
            },
            'connection_details': {
                'aws_access_key_id': 'test-key',
                'aws_secret_access_key': 'test-secret',
                'region': 'us-east-1'
            }
        }
        
        module = S3Module(config)
        
        mock_client = Mock()
        mock_client.put_object = Mock()
        module.s3_client = mock_client
        
        payload = {'data': 'test'}
        headers = {'Content-Type': 'application/json', 'X-Custom-Header': 'value'}
        
        await module.process(payload, headers)
        
        call_kwargs = mock_client.put_object.call_args[1]
        assert 'Metadata' in call_kwargs
        assert 'content_type' in call_kwargs['Metadata']
        assert 'x_custom_header' in call_kwargs['Metadata']
    
    @pytest.mark.asyncio
    async def test_process_without_bucket(self):
        """Test processing without bucket specified."""
        config = {
            'module-config': {
                'prefix': 'webhooks',
                'filename_pattern': 'webhook-{uuid}.json'
            },
            'connection_details': {}
        }
        
        module = S3Module(config)
        module.s3_client = Mock()
        
        with pytest.raises(Exception, match="S3 bucket not specified"):
            await module.process({'data': 'test'}, {})
    
    @pytest.mark.asyncio
    async def test_process_auto_setup(self):
        """Test that process calls setup if client not initialized."""
        config = {
            'module-config': {
                'bucket': 'test-bucket',
                'prefix': 'webhooks',
                'filename_pattern': 'webhook-{uuid}.json'
            },
            'connection_details': {
                'aws_access_key_id': 'test-key',
                'aws_secret_access_key': 'test-secret',
                'region': 'us-east-1'
            }
        }
        
        module = S3Module(config)
        module.s3_client = None
        
        with patch.object(module, 'setup', AsyncMock()) as mock_setup, \
             patch('src.modules.s3.boto3') as mock_boto3:
            
            mock_client = Mock()
            mock_client.put_object = Mock()
            mock_boto3.client.return_value = mock_client
            mock_setup.side_effect = lambda: setattr(module, 's3_client', mock_client)
            
            await module.process({'data': 'test'}, {})
            
            mock_setup.assert_called_once()


class TestS3ModuleErrorHandling:
    """Test S3 error handling."""
    
    @pytest.mark.asyncio
    async def test_process_with_client_error(self):
        """Test processing with S3 ClientError."""
        config = {
            'module-config': {
                'bucket': 'test-bucket',
                'prefix': 'webhooks',
                'filename_pattern': 'webhook-{uuid}.json'
            },
            'connection_details': {}
        }
        
        module = S3Module(config)
        
        mock_client = Mock()
        error_response = {
            'Error': {
                'Code': 'AccessDenied',
                'Message': 'Access denied'
            }
        }
        mock_client.put_object.side_effect = ClientError(error_response, 'PutObject')
        module.s3_client = mock_client
        
        with pytest.raises(Exception):
            await module.process({'data': 'test'}, {})
    
    @pytest.mark.asyncio
    async def test_process_with_generic_error(self):
        """Test processing with generic exception."""
        config = {
            'module-config': {
                'bucket': 'test-bucket',
                'prefix': 'webhooks',
                'filename_pattern': 'webhook-{uuid}.json'
            },
            'connection_details': {}
        }
        
        module = S3Module(config)
        
        mock_client = Mock()
        mock_client.put_object.side_effect = Exception("Network error")
        module.s3_client = mock_client
        
        with pytest.raises(Exception):
            await module.process({'data': 'test'}, {})
    
    @pytest.mark.asyncio
    async def test_process_with_invalid_filename_after_replacement(self):
        """Test processing with invalid filename pattern (invalid placeholder)."""
        config = {
            'module-config': {
                'bucket': 'test-bucket',
                'prefix': 'webhooks',
                'filename_pattern': 'webhook-{invalid_placeholder}.json'
            },
            'connection_details': {}
        }
        
        # This should raise ValueError during initialization due to invalid placeholder
        with pytest.raises(ValueError, match="Invalid filename pattern format"):
            S3Module(config)


class TestS3ModuleFilenameGeneration:
    """Test filename generation and validation."""
    
    @pytest.mark.asyncio
    async def test_process_with_uuid_placeholder(self):
        """Test filename generation with UUID placeholder."""
        config = {
            'module-config': {
                'bucket': 'test-bucket',
                'prefix': 'webhooks',
                'filename_pattern': 'webhook-{uuid}.json'
            },
            'connection_details': {}
        }
        
        module = S3Module(config)
        
        mock_client = Mock()
        mock_client.put_object = Mock()
        module.s3_client = mock_client
        
        await module.process({'data': 'test'}, {})
        
        call_kwargs = mock_client.put_object.call_args[1]
        key = call_kwargs['Key']
        # Should contain UUID (36 chars with dashes)
        assert 'webhook-' in key
        assert '.json' in key
    
    @pytest.mark.asyncio
    async def test_process_with_timestamp_placeholder(self):
        """Test filename generation with timestamp placeholder."""
        config = {
            'module-config': {
                'bucket': 'test-bucket',
                'prefix': 'webhooks',
                'filename_pattern': 'webhook-{timestamp}.json'
            },
            'connection_details': {}
        }
        
        module = S3Module(config)
        
        mock_client = Mock()
        mock_client.put_object = Mock()
        module.s3_client = mock_client
        
        await module.process({'data': 'test'}, {})
        
        call_kwargs = mock_client.put_object.call_args[1]
        key = call_kwargs['Key']
        # Should contain timestamp
        assert 'webhook-' in key
        assert '.json' in key

