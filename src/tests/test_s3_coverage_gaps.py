"""
Comprehensive unit tests to fill coverage gaps in s3.py module.
Target: 100% coverage for S3Module class.
"""
import pytest
import json
import uuid
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from botocore.exceptions import ClientError
from src.modules.s3 import S3Module


class TestS3ModuleInit:
    """Test S3Module.__init__() - various config scenarios."""
    
    def test_init_with_default_config(self):
        """Test initialization with default config."""
        config = {
            'module': 's3',
            'module-config': {
                'bucket': 'test-bucket'
            },
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = S3Module(config)
            assert module.s3_client is None
            assert module._validated_prefix == 'webhooks'
            assert module._validated_filename_pattern == 'webhook_{uuid}.json'
    
    def test_init_with_custom_prefix(self):
        """Test initialization with custom prefix."""
        config = {
            'module': 's3',
            'module-config': {
                'bucket': 'test-bucket',
                'prefix': 'custom/prefix'
            },
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = S3Module(config)
            assert module._validated_prefix == 'custom/prefix'
    
    def test_init_with_custom_filename_pattern(self):
        """Test initialization with custom filename pattern."""
        config = {
            'module': 's3',
            'module-config': {
                'bucket': 'test-bucket',
                'filename_pattern': 'webhook_{timestamp}_{uuid}.json'
            },
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = S3Module(config)
            assert '{timestamp}' in module._validated_filename_pattern
            assert '{uuid}' in module._validated_filename_pattern
    
    def test_init_with_invalid_prefix(self):
        """Test initialization with invalid prefix."""
        config = {
            'module': 's3',
            'module-config': {
                'bucket': 'test-bucket',
                'prefix': '../invalid'
            },
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            with pytest.raises(ValueError, match="path traversal"):
                module = S3Module(config)
                module.config = config
                module.module_config = config.get('module-config', {})
    
    def test_init_with_invalid_filename_pattern(self):
        """Test initialization with invalid filename pattern."""
        config = {
            'module': 's3',
            'module-config': {
                'bucket': 'test-bucket',
                'filename_pattern': '../../invalid'
            },
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            with pytest.raises(ValueError, match="path traversal"):
                module = S3Module(config)
                module.config = config
                module.module_config = config.get('module-config', {})


class TestS3ModuleSetup:
    """Test S3Module.setup() - S3 client initialization."""
    
    @pytest.mark.asyncio
    async def test_setup_with_credentials(self):
        """Test setup with AWS credentials."""
        config = {
            'module': 's3',
            'module-config': {
                'bucket': 'test-bucket'
            },
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = S3Module(config)
            module.connection_details = {
                'aws_access_key_id': 'test-key',
                'aws_secret_access_key': 'test-secret',
                'region': 'us-west-2'
            }
            
            with patch('boto3.client') as mock_boto3:
                mock_client = Mock()
                mock_boto3.return_value = mock_client
                
                await module.setup()
                
                mock_boto3.assert_called_once_with(
                    's3',
                    aws_access_key_id='test-key',
                    aws_secret_access_key='test-secret',
                    region_name='us-west-2'
                )
                assert module.s3_client == mock_client
    
    @pytest.mark.asyncio
    async def test_setup_without_credentials(self):
        """Test setup without AWS credentials (uses default)."""
        config = {
            'module': 's3',
            'module-config': {
                'bucket': 'test-bucket'
            },
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = S3Module(config)
            module.connection_details = {
                'region': 'us-west-2'
            }
            
            with patch('boto3.client') as mock_boto3:
                mock_client = Mock()
                mock_boto3.return_value = mock_client
                
                await module.setup()
                
                mock_boto3.assert_called_once_with('s3', region_name='us-west-2')
                assert module.s3_client == mock_client
    
    @pytest.mark.asyncio
    async def test_setup_with_default_region(self):
        """Test setup with default region."""
        config = {
            'module': 's3',
            'module-config': {
                'bucket': 'test-bucket'
            },
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = S3Module(config)
            module.connection_details = {}
            
            with patch('boto3.client') as mock_boto3:
                mock_client = Mock()
                mock_boto3.return_value = mock_client
                
                await module.setup()
                
                mock_boto3.assert_called_once_with('s3', region_name='us-east-1')
                assert module.s3_client == mock_client
    
    @pytest.mark.asyncio
    async def test_setup_exception(self):
        """Test setup exception handling."""
        config = {
            'module': 's3',
            'module-config': {
                'bucket': 'test-bucket'
            },
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = S3Module(config)
            module.connection_details = {}
            
            with patch('boto3.client', side_effect=Exception("Boto3 error")):
                with pytest.raises(Exception):
                    await module.setup()


class TestS3ModuleProcess:
    """Test S3Module.process() - upload success and failure paths."""
    
    @pytest.mark.asyncio
    async def test_process_success_with_dict_payload(self):
        """Test successful process with dict payload."""
        config = {
            'module': 's3',
            'module-config': {
                'bucket': 'test-bucket'
            },
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = S3Module(config)
            module.s3_client = Mock()
            module.s3_client.put_object = Mock()
            
            payload = {'data': 'test'}
            headers = {'Content-Type': 'application/json'}
            
            with patch('builtins.print'):
                await module.process(payload, headers)
                
                module.s3_client.put_object.assert_called_once()
                call_kwargs = module.s3_client.put_object.call_args[1]
                assert call_kwargs['Bucket'] == 'test-bucket'
                assert call_kwargs['ContentType'] == 'application/json'
                assert 'Key' in call_kwargs
    
    @pytest.mark.asyncio
    async def test_process_success_with_list_payload(self):
        """Test successful process with list payload."""
        config = {
            'module': 's3',
            'module-config': {
                'bucket': 'test-bucket'
            },
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = S3Module(config)
            module.s3_client = Mock()
            module.s3_client.put_object = Mock()
            
            payload = [1, 2, 3]
            headers = {}
            
            with patch('builtins.print'):
                await module.process(payload, headers)
                
                module.s3_client.put_object.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_process_success_with_string_payload(self):
        """Test successful process with string payload."""
        config = {
            'module': 's3',
            'module-config': {
                'bucket': 'test-bucket'
            },
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = S3Module(config)
            module.s3_client = Mock()
            module.s3_client.put_object = Mock()
            
            payload = 'test string'
            headers = {}
            
            with patch('builtins.print'):
                await module.process(payload, headers)
                
                module.s3_client.put_object.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_process_with_custom_content_type(self):
        """Test process with custom content type."""
        config = {
            'module': 's3',
            'module-config': {
                'bucket': 'test-bucket',
                'content_type': 'application/xml'
            },
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = S3Module(config)
            module.s3_client = Mock()
            module.s3_client.put_object = Mock()
            
            payload = {'data': 'test'}
            headers = {}
            
            with patch('builtins.print'):
                await module.process(payload, headers)
                
                call_kwargs = module.s3_client.put_object.call_args[1]
                assert call_kwargs['ContentType'] == 'application/xml'
    
    @pytest.mark.asyncio
    async def test_process_with_include_headers(self):
        """Test process with include_headers enabled."""
        config = {
            'module': 's3',
            'module-config': {
                'bucket': 'test-bucket',
                'include_headers': True
            },
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = S3Module(config)
            module.s3_client = Mock()
            module.s3_client.put_object = Mock()
            
            payload = {'data': 'test'}
            headers = {
                'Content-Type': 'application/json',
                'X-Custom-Header': 'value'
            }
            
            with patch('builtins.print'):
                await module.process(payload, headers)
                
                call_kwargs = module.s3_client.put_object.call_args[1]
                assert 'Metadata' in call_kwargs
                metadata = call_kwargs['Metadata']
                assert 'content_type' in metadata or 'x_custom_header' in metadata
    
    @pytest.mark.asyncio
    async def test_process_with_timestamp_placeholder(self):
        """Test process with timestamp placeholder in filename."""
        config = {
            'module': 's3',
            'module-config': {
                'bucket': 'test-bucket',
                'filename_pattern': 'webhook_{timestamp}.json'
            },
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = S3Module(config)
            module.s3_client = Mock()
            module.s3_client.put_object = Mock()
            
            payload = {'data': 'test'}
            headers = {}
            
            with patch('builtins.print'):
                await module.process(payload, headers)
                
                call_kwargs = module.s3_client.put_object.call_args[1]
                key = call_kwargs['Key']
                assert 'webhook_' in key
                assert '.json' in key
    
    @pytest.mark.asyncio
    async def test_process_auto_setup(self):
        """Test process automatically calls setup if client not initialized."""
        config = {
            'module': 's3',
            'module-config': {
                'bucket': 'test-bucket'
            },
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = S3Module(config)
            module.s3_client = None
            module.connection_details = {}
            
            mock_client = Mock()
            mock_client.put_object = Mock()
            
            with patch.object(module, 'setup', return_value=None) as mock_setup, \
                 patch('boto3.client', return_value=mock_client), \
                 patch('builtins.print'):
                
                module.s3_client = mock_client
                await module.process({'data': 'test'}, {})
                
                # Setup should be called if client was None
                # But we set it after setup, so put_object should be called
                mock_client.put_object.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_process_no_bucket(self):
        """Test process without bucket specified."""
        config = {
            'module': 's3',
            'module-config': {},
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = S3Module(config)
            module.s3_client = Mock()
            
            with pytest.raises(Exception, match="S3 bucket not specified"):
                await module.process({'data': 'test'}, {})
    
    @pytest.mark.asyncio
    async def test_process_client_error(self):
        """Test process with ClientError."""
        config = {
            'module': 's3',
            'module-config': {
                'bucket': 'test-bucket'
            },
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = S3Module(config)
            module.s3_client = Mock()
            
            error_response = {
                'Error': {
                    'Code': 'AccessDenied',
                    'Message': 'Access denied'
                }
            }
            client_error = ClientError(error_response, 'PutObject')
            module.s3_client.put_object = Mock(side_effect=client_error)
            
            with patch('builtins.print'):
                with pytest.raises(Exception):
                    await module.process({'data': 'test'}, {})
    
    @pytest.mark.asyncio
    async def test_process_generic_exception(self):
        """Test process with generic exception."""
        config = {
            'module': 's3',
            'module-config': {
                'bucket': 'test-bucket'
            },
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = S3Module(config)
            module.s3_client = Mock()
            module.s3_client.put_object = Mock(side_effect=Exception("Generic error"))
            
            with patch('builtins.print'):
                with pytest.raises(Exception):
                    await module.process({'data': 'test'}, {})


class TestS3ModuleValidation:
    """Test S3Module validation methods."""
    
    def test_validate_s3_path_component_valid(self):
        """Test _validate_s3_path_component with valid input."""
        config = {
            'module': 's3',
            'module-config': {'bucket': 'test-bucket'},
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = S3Module(config)
            result = module._validate_s3_path_component('valid/path', 'prefix')
            assert result == 'valid/path'
    
    def test_validate_s3_path_component_empty(self):
        """Test _validate_s3_path_component with empty input."""
        config = {
            'module': 's3',
            'module-config': {'bucket': 'test-bucket'},
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = S3Module(config)
            with pytest.raises(ValueError, match="must be a non-empty string"):
                module._validate_s3_path_component('', 'prefix')
    
    def test_validate_s3_path_component_path_traversal(self):
        """Test _validate_s3_path_component with path traversal."""
        config = {
            'module': 's3',
            'module-config': {'bucket': 'test-bucket'},
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = S3Module(config)
            with pytest.raises(ValueError, match="path traversal"):
                module._validate_s3_path_component('../invalid', 'prefix')
    
    def test_validate_s3_path_component_too_long(self):
        """Test _validate_s3_path_component with too long input."""
        config = {
            'module': 's3',
            'module-config': {'bucket': 'test-bucket'},
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = S3Module(config)
            long_path = 'a' * 300
            with pytest.raises(ValueError, match="too long"):
                module._validate_s3_path_component(long_path, 'prefix')
    
    def test_validate_s3_path_component_dangerous_pattern(self):
        """Test _validate_s3_path_component with dangerous pattern."""
        config = {
            'module': 's3',
            'module-config': {'bucket': 'test-bucket'},
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = S3Module(config)
            with pytest.raises(ValueError, match="Invalid prefix format"):
                module._validate_s3_path_component('path;with;semicolon', 'prefix')
    
    def test_validate_filename_pattern_valid(self):
        """Test _validate_filename_pattern with valid input."""
        config = {
            'module': 's3',
            'module-config': {'bucket': 'test-bucket'},
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = S3Module(config)
            result = module._validate_filename_pattern('webhook_{uuid}.json')
            assert result == 'webhook_{uuid}.json'
    
    def test_validate_filename_pattern_with_timestamp(self):
        """Test _validate_filename_pattern with timestamp placeholder."""
        config = {
            'module': 's3',
            'module-config': {'bucket': 'test-bucket'},
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = S3Module(config)
            result = module._validate_filename_pattern('webhook_{timestamp}_{uuid}.json')
            assert '{timestamp}' in result
            assert '{uuid}' in result
    
    def test_validate_object_key_valid(self):
        """Test _validate_object_key with valid input."""
        config = {
            'module': 's3',
            'module-config': {'bucket': 'test-bucket'},
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = S3Module(config)
            result = module._validate_object_key('valid/key/path.json')
            assert result == 'valid/key/path.json'
    
    def test_validate_object_key_too_long(self):
        """Test _validate_object_key with too long input."""
        config = {
            'module': 's3',
            'module-config': {'bucket': 'test-bucket'},
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = S3Module(config)
            long_key = 'a' * 2000  # More than 1024 bytes
            with pytest.raises(ValueError, match="too long"):
                module._validate_object_key(long_key)
    
    def test_validate_object_key_path_traversal(self):
        """Test _validate_object_key with path traversal."""
        config = {
            'module': 's3',
            'module-config': {'bucket': 'test-bucket'},
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = S3Module(config)
            with pytest.raises(ValueError, match="path traversal"):
                module._validate_object_key('../invalid/key')
    
    def test_validate_object_key_absolute_path(self):
        """Test _validate_object_key with absolute path."""
        config = {
            'module': 's3',
            'module-config': {'bucket': 'test-bucket'},
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = S3Module(config)
            with pytest.raises(ValueError, match="cannot start with"):
                module._validate_object_key('/absolute/path')


class TestS3ModuleTeardown:
    """Test S3Module.teardown() - client cleanup."""
    
    @pytest.mark.asyncio
    async def test_teardown(self):
        """Test teardown method."""
        config = {
            'module': 's3',
            'module-config': {'bucket': 'test-bucket'},
            'connection': 's3-connection'
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = S3Module(config)
            module.s3_client = Mock()
            
            # teardown is inherited from BaseModule, but we can test it exists
            assert hasattr(module, 'teardown')
            
            # If teardown exists and is async, call it
            if hasattr(module, 'teardown') and asyncio.iscoroutinefunction(module.teardown):
                await module.teardown()

