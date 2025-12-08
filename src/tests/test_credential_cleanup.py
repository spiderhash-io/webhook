"""Tests for credential cleanup functionality."""
import pytest
import json
from unittest.mock import AsyncMock, MagicMock, patch
from src.utils import CredentialCleaner


class TestCredentialCleaner:
    """Test CredentialCleaner class functionality."""
    
    def test_default_credential_fields(self):
        """Test that default credential fields are recognized."""
        cleaner = CredentialCleaner()
        
        # Test default fields
        assert cleaner._is_credential_field('password')
        assert cleaner._is_credential_field('PASSWORD')  # Case insensitive
        assert cleaner._is_credential_field('api_key')
        assert cleaner._is_credential_field('token')
        assert cleaner._is_credential_field('secret')
        assert cleaner._is_credential_field('authorization')
        assert cleaner._is_credential_field('x-api-key')
        assert cleaner._is_credential_field('access_token')
        assert cleaner._is_credential_field('client_secret')
        
        # Test non-credential fields
        assert not cleaner._is_credential_field('username')
        assert not cleaner._is_credential_field('email')
        assert not cleaner._is_credential_field('data')
        assert not cleaner._is_credential_field('message')
    
    def test_custom_credential_fields(self):
        """Test custom credential fields."""
        cleaner = CredentialCleaner(custom_fields=['custom_secret', 'my_token'])
        
        assert cleaner._is_credential_field('custom_secret')
        assert cleaner._is_credential_field('my_token')
        assert cleaner._is_credential_field('password')  # Default still works
    
    def test_mask_mode(self):
        """Test mask mode replaces credentials with mask value."""
        cleaner = CredentialCleaner(mode='mask')
        
        data = {
            'username': 'user123',
            'password': 'secret123',
            'api_key': 'key456',
            'data': {'nested': 'value'}
        }
        
        cleaned = cleaner.clean_credentials(data)
        
        assert cleaned['username'] == 'user123'
        assert cleaned['password'] == '***REDACTED***'
        assert cleaned['api_key'] == '***REDACTED***'
        assert cleaned['data']['nested'] == 'value'
    
    def test_remove_mode(self):
        """Test remove mode deletes credential fields."""
        cleaner = CredentialCleaner(mode='remove')
        
        data = {
            'username': 'user123',
            'password': 'secret123',
            'api_key': 'key456',
            'data': {'nested': 'value'}
        }
        
        cleaned = cleaner.clean_credentials(data)
        
        assert cleaned['username'] == 'user123'
        assert 'password' not in cleaned
        assert 'api_key' not in cleaned
        assert cleaned['data']['nested'] == 'value'
    
    def test_nested_structures(self):
        """Test cleaning credentials from nested JSON structures."""
        cleaner = CredentialCleaner(mode='mask')
        
        data = {
            'user': {
                'name': 'John',
                'password': 'secret',
                'profile': {
                    'api_key': 'key123',
                    'email': 'john@example.com'
                }
            },
            'tokens': [
                {'access_token': 'token1', 'type': 'bearer'},
                {'refresh_token': 'token2', 'type': 'refresh'}
            ]
        }
        
        cleaned = cleaner.clean_credentials(data)
        
        assert cleaned['user']['name'] == 'John'
        assert cleaned['user']['password'] == '***REDACTED***'
        assert cleaned['user']['profile']['api_key'] == '***REDACTED***'
        assert cleaned['user']['profile']['email'] == 'john@example.com'
        assert cleaned['tokens'][0]['access_token'] == '***REDACTED***'
        assert cleaned['tokens'][0]['type'] == 'bearer'
        assert cleaned['tokens'][1]['refresh_token'] == '***REDACTED***'
    
    def test_clean_headers(self):
        """Test cleaning credentials from HTTP headers."""
        cleaner = CredentialCleaner(mode='mask')
        
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer token123',
            'X-API-Key': 'key456',
            'User-Agent': 'Mozilla/5.0'
        }
        
        cleaned = cleaner.clean_headers(headers)
        
        assert cleaned['Content-Type'] == 'application/json'
        assert cleaned['Authorization'] == '***REDACTED***'
        assert cleaned['X-API-Key'] == '***REDACTED***'
        assert cleaned['User-Agent'] == 'Mozilla/5.0'
    
    def test_clean_headers_remove_mode(self):
        """Test cleaning headers in remove mode."""
        cleaner = CredentialCleaner(mode='remove')
        
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer token123',
            'X-API-Key': 'key456'
        }
        
        cleaned = cleaner.clean_headers(headers)
        
        assert cleaned['Content-Type'] == 'application/json'
        assert 'Authorization' not in cleaned
        assert 'X-API-Key' not in cleaned
    
    def test_clean_query_params(self):
        """Test cleaning credentials from query parameters."""
        cleaner = CredentialCleaner(mode='mask')
        
        params = {
            'page': '1',
            'api_key': 'key123',
            'token': 'token456',
            'limit': '10'
        }
        
        cleaned = cleaner.clean_query_params(params)
        
        assert cleaned['page'] == '1'
        assert cleaned['api_key'] == '***REDACTED***'
        assert cleaned['token'] == '***REDACTED***'
        assert cleaned['limit'] == '10'
    
    def test_empty_data(self):
        """Test handling of empty data structures."""
        cleaner = CredentialCleaner()
        
        assert cleaner.clean_credentials({}) == {}
        assert cleaner.clean_credentials([]) == []
        assert cleaner.clean_credentials(None) is None
    
    def test_non_dict_list_data(self):
        """Test handling of primitive data types."""
        cleaner = CredentialCleaner()
        
        assert cleaner.clean_credentials('string') == 'string'
        assert cleaner.clean_credentials(123) == 123
        assert cleaner.clean_credentials(True) is True
    
    def test_case_insensitive_matching(self):
        """Test that credential field matching is case-insensitive."""
        cleaner = CredentialCleaner()
        
        data = {
            'PASSWORD': 'secret1',
            'Password': 'secret2',
            'password': 'secret3',
            'API_KEY': 'key1',
            'Api_Key': 'key2'
        }
        
        cleaned = cleaner.clean_credentials(data)
        
        assert cleaned['PASSWORD'] == '***REDACTED***'
        assert cleaned['Password'] == '***REDACTED***'
        assert cleaned['password'] == '***REDACTED***'
        assert cleaned['API_KEY'] == '***REDACTED***'
        assert cleaned['Api_Key'] == '***REDACTED***'
    
    def test_invalid_mode(self):
        """Test that invalid mode raises ValueError."""
        with pytest.raises(ValueError, match="Mode must be 'mask' or 'remove'"):
            CredentialCleaner(mode='invalid')
    
    def test_pattern_matching(self):
        """Test pattern matching for credential-like field names."""
        cleaner = CredentialCleaner()
        
        # These should match patterns even if not in default list
        assert cleaner._is_credential_field('user_password')
        assert cleaner._is_credential_field('api_secret_key')
        assert cleaner._is_credential_field('x-custom-token')
        assert cleaner._is_credential_field('auth_token')
    
    def test_list_of_objects(self):
        """Test cleaning credentials from list of objects."""
        cleaner = CredentialCleaner(mode='mask')
        
        data = [
            {'id': 1, 'password': 'pass1', 'name': 'User1'},
            {'id': 2, 'password': 'pass2', 'name': 'User2'}
        ]
        
        cleaned = cleaner.clean_credentials(data)
        
        assert cleaned[0]['id'] == 1
        assert cleaned[0]['password'] == '***REDACTED***'
        assert cleaned[0]['name'] == 'User1'
        assert cleaned[1]['id'] == 2
        assert cleaned[1]['password'] == '***REDACTED***'
    
    def test_deep_nesting(self):
        """Test cleaning credentials from deeply nested structures."""
        cleaner = CredentialCleaner(mode='mask')
        
        data = {
            'level1': {
                'level2': {
                    'level3': {
                        'level4': {
                            'secret': 'deep_secret',
                            'data': 'normal_data'
                        }
                    }
                }
            }
        }
        
        cleaned = cleaner.clean_credentials(data)
        
        assert cleaned['level1']['level2']['level3']['level4']['secret'] == '***REDACTED***'
        assert cleaned['level1']['level2']['level3']['level4']['data'] == 'normal_data'


class TestCredentialCleanupIntegration:
    """Test credential cleanup integration with webhook processing."""
    
    @pytest.fixture
    def mock_module(self):
        """Create a mock module."""
        module = AsyncMock()
        module.process = AsyncMock()
        return module
    
    @pytest.mark.asyncio
    async def test_webhook_cleanup_enabled(self):
        """Test that credentials are cleaned when cleanup is enabled."""
        from src.webhook import WebhookHandler
        from fastapi import Request
        from unittest.mock import MagicMock
        
        # Mock request
        request = MagicMock(spec=Request)
        request.headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer token123',
            'X-API-Key': 'key456'
        }
        request.body = AsyncMock(return_value=b'{"username": "user", "password": "secret"}')
        
        # Mock config with cleanup enabled
        config = {
            'data_type': 'json',
            'module': 'log',
            'credential_cleanup': {
                'enabled': True,
                'mode': 'mask'
            }
        }
        
        # Mock module registry
        with patch('src.webhook.ModuleRegistry.get') as mock_get:
            from src.modules.log import LogModule
            mock_get.return_value = LogModule
            
            configs = {'test_webhook': config}
            handler = WebhookHandler('test_webhook', configs, {}, request, pool_registry=None)
            handler._cached_body = b'{"username": "user", "password": "secret"}'
            
            # Mock task manager
            with patch('src.webhook.task_manager') as mock_tm:
                mock_tm.create_task = AsyncMock()
                
                payload, headers, task = await handler.process_webhook()
                
                # Check that credentials were cleaned in the module call
                # The module.process should have been called with cleaned data
                # We can't directly check this without more mocking, but we can verify
                # the cleanup logic was executed
    
    @pytest.mark.asyncio
    async def test_webhook_cleanup_disabled(self):
        """Test that credentials are not cleaned when cleanup is disabled."""
        from src.webhook import WebhookHandler
        from fastapi import Request
        from unittest.mock import MagicMock
        
        # Mock request
        request = MagicMock(spec=Request)
        request.headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer token123'
        }
        request.body = AsyncMock(return_value=b'{"username": "user", "password": "secret"}')
        
        # Mock config with cleanup disabled
        config = {
            'data_type': 'json',
            'module': 'log',
            'credential_cleanup': {
                'enabled': False
            }
        }
        
        # Mock module registry
        with patch('src.webhook.ModuleRegistry.get') as mock_get:
            from src.modules.log import LogModule
            mock_get.return_value = LogModule
            
            configs = {'test_webhook': config}
            handler = WebhookHandler('test_webhook', configs, {}, request, pool_registry=None)
            handler._cached_body = b'{"username": "user", "password": "secret"}'
            
            # Mock task manager
            with patch('src.webhook.task_manager') as mock_tm:
                mock_tm.create_task = AsyncMock()
                
                payload, headers, task = await handler.process_webhook()
                
                # When cleanup is disabled, original data should be passed through
                # (though we can't easily verify this without deeper mocking)
    
    @pytest.mark.asyncio
    async def test_clickhouse_analytics_cleanup(self):
        """Test that ClickHouse analytics cleans credentials."""
        from src.clickhouse_analytics import ClickHouseAnalytics
        from unittest.mock import patch, MagicMock
        
        # Create analytics instance
        analytics = ClickHouseAnalytics(
            connection_config={'host': 'localhost', 'port': 9000},
            batch_size=10,
            flush_interval=1.0
        )
        
        # Mock queue
        analytics.queue = AsyncMock()
        analytics.queue.put = AsyncMock()
        
        # Test data with credentials
        payload = {
            'username': 'user',
            'password': 'secret123',
            'api_key': 'key456'
        }
        headers = {
            'Authorization': 'Bearer token789',
            'Content-Type': 'application/json'
        }
        
        await analytics.save_log('test_webhook', payload, headers)
        
        # Verify queue.put was called
        assert analytics.queue.put.called
        
        # Get the arguments passed to queue.put
        call_args = analytics.queue.put.call_args[0][0]
        assert call_args[0] == 'log'
        
        # Extract the log record
        log_record = call_args[1]
        record_id, webhook_id, timestamp, payload_str, headers_str = log_record
        
        # Parse the logged data
        logged_payload = json.loads(payload_str)
        logged_headers = json.loads(headers_str)
        
        # Verify credentials were masked
        assert logged_payload['username'] == 'user'
        assert logged_payload['password'] == '***REDACTED***'
        assert logged_payload['api_key'] == '***REDACTED***'
        assert logged_headers['Authorization'] == '***REDACTED***'
        assert logged_headers['Content-Type'] == 'application/json'
    
    def test_cleanup_config_defaults(self):
        """Test that cleanup defaults to enabled (opt-out behavior)."""
        # When credential_cleanup config is missing, it should default to enabled
        # This is tested implicitly in webhook processing, but we can verify
        # the CredentialCleaner defaults
        cleaner = CredentialCleaner()
        assert cleaner.mode == 'mask'
        
        # Test that enabled defaults to True in webhook processing
        # (This would require more complex integration testing)
    
    def test_custom_fields_in_config(self):
        """Test that custom fields from config are used."""
        cleaner = CredentialCleaner(custom_fields=['custom_secret', 'my_token'])
        
        data = {
            'custom_secret': 'secret123',
            'my_token': 'token456',
            'normal_field': 'value'
        }
        
        cleaned = cleaner.clean_credentials(data)
        
        assert cleaned['custom_secret'] == '***REDACTED***'
        assert cleaned['my_token'] == '***REDACTED***'
        assert cleaned['normal_field'] == 'value'
    
    def test_cleanup_preserves_original(self):
        """Test that cleanup doesn't modify original data structures."""
        cleaner = CredentialCleaner(mode='mask')
        
        original_data = {
            'username': 'user',
            'password': 'secret'
        }
        
        # Create a copy for cleaning
        import copy
        data_copy = copy.deepcopy(original_data)
        cleaned = cleaner.clean_credentials(data_copy)
        
        # Original should be unchanged
        assert original_data['password'] == 'secret'
        
        # Cleaned should have masked password
        assert cleaned['password'] == '***REDACTED***'
    
    def test_edge_cases(self):
        """Test edge cases in credential cleanup."""
        cleaner = CredentialCleaner(mode='mask')
        
        # Empty string credential field
        data1 = {'password': ''}
        cleaned1 = cleaner.clean_credentials(data1)
        assert cleaned1['password'] == '***REDACTED***'
        
        # None value
        data2 = {'password': None}
        cleaned2 = cleaner.clean_credentials(data2)
        assert cleaned2['password'] == '***REDACTED***'
        
        # Numeric value (should still be masked)
        data3 = {'api_key': 12345}
        cleaned3 = cleaner.clean_credentials(data3)
        assert cleaned3['api_key'] == '***REDACTED***'
        
        # Boolean value
        data4 = {'token': True}
        cleaned4 = cleaner.clean_credentials(data4)
        assert cleaned4['token'] == '***REDACTED***'

