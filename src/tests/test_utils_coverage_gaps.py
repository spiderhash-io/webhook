"""
Comprehensive unit tests to fill coverage gaps in utils.py.
Target: 100% coverage for utility functions and classes.
"""
import pytest
import os
import asyncio
import time
from unittest.mock import Mock, AsyncMock, patch, MagicMock, mock_open
from datetime import datetime, timedelta, timezone
from src.utils import (
    sanitize_error_message,
    _sanitize_context,
    _sanitize_env_value,
    load_env_vars,
    save_to_disk,
    print_to_stdout,
    EndpointStats,
    RedisEndpointStats,
    CredentialCleaner
)


class TestSanitizeContext:
    """Test _sanitize_context() - all sanitization paths."""
    
    def test_sanitize_context_safe(self):
        """Test sanitize_context with safe context."""
        result = _sanitize_context("webhook_processing")
        assert result == "webhook_processing"
    
    def test_sanitize_context_with_url(self):
        """Test sanitize_context with URL in context."""
        result = _sanitize_context("http://localhost:8000/webhook")
        assert result == "processing"
    
    def test_sanitize_context_with_file_path(self):
        """Test sanitize_context with file path."""
        result = _sanitize_context("/etc/passwd")
        assert result == "processing"
    
    def test_sanitize_context_with_connection_string(self):
        """Test sanitize_context with connection string."""
        result = _sanitize_context("postgresql://user:pass@host/db")
        assert result == "processing"
    
    def test_sanitize_context_with_localhost(self):
        """Test sanitize_context with localhost."""
        result = _sanitize_context("localhost:8000")
        assert result == "processing"
    
    def test_sanitize_context_with_private_ip(self):
        """Test sanitize_context with private IP."""
        result = _sanitize_context("192.168.1.1:5432")
        assert result == "processing"
    
    def test_sanitize_context_none(self):
        """Test sanitize_context with None."""
        result = _sanitize_context(None)
        assert result == "processing"
    
    def test_sanitize_context_not_string(self):
        """Test sanitize_context with non-string."""
        result = _sanitize_context(123)
        assert result == "processing"


class TestSanitizeEnvValue:
    """Test _sanitize_env_value() - all sanitization paths."""
    
    def test_sanitize_env_value_safe(self):
        """Test sanitize_env_value with safe value."""
        result = _sanitize_env_value("safe_value", "test_key")
        assert result == "safe_value"
    
    def test_sanitize_env_value_with_null_byte(self):
        """Test sanitize_env_value with null byte."""
        with patch('builtins.print'):
            result = _sanitize_env_value("value\x00test", "test_key")
            assert '\x00' not in result
    
    def test_sanitize_env_value_with_dangerous_url_scheme(self):
        """Test sanitize_env_value with dangerous URL scheme."""
        with patch('builtins.print'):
            result = _sanitize_env_value("javascript:alert(1)", "url_key")
            assert not result.startswith("javascript:")
    
    def test_sanitize_env_value_with_command_injection(self):
        """Test sanitize_env_value with command injection characters."""
        with patch('builtins.print'):
            result = _sanitize_env_value("value;rm -rf /", "test_key")
            assert ';' not in result
    
    def test_sanitize_env_value_with_sql_injection(self):
        """Test sanitize_env_value with SQL injection patterns."""
        with patch('builtins.print'):
            result = _sanitize_env_value("value'; DROP TABLE users; --", "sql_key")
            assert "DROP TABLE" not in result
    
    def test_sanitize_env_value_with_path_traversal(self):
        """Test sanitize_env_value with path traversal."""
        with patch('builtins.print'):
            result = _sanitize_env_value("../../etc/passwd", "test_key")
            assert '..' not in result
    
    def test_sanitize_env_value_with_absolute_path(self):
        """Test sanitize_env_value with absolute path in non-path context."""
        with patch('builtins.print'):
            result = _sanitize_env_value("/etc/passwd", "test_key")
            assert not result.startswith('/')
    
    def test_sanitize_env_value_with_command_keywords(self):
        """Test sanitize_env_value with command keywords."""
        with patch('builtins.print'):
            result = _sanitize_env_value("rm -rf /", "test_key")
            assert "rm -rf" not in result
    
    def test_sanitize_env_value_too_long(self):
        """Test sanitize_env_value with too long value."""
        long_value = "a" * 5000
        with patch('builtins.print'):
            result = _sanitize_env_value(long_value, "test_key")
            assert len(result) <= 4096
    
    def test_sanitize_env_value_completely_sanitized(self):
        """Test sanitize_env_value that becomes empty after sanitization."""
        with patch('builtins.print'):
            result = _sanitize_env_value(";|&`$", "test_key")
            assert result == "sanitized_value"
    
    def test_sanitize_env_value_not_string(self):
        """Test sanitize_env_value with non-string."""
        result = _sanitize_env_value(123, "test_key")
        assert result == 123


class TestLoadEnvVars:
    """Test load_env_vars() - all recursion and edge cases."""
    
    def test_load_env_vars_simple_replacement(self):
        """Test load_env_vars with simple replacement."""
        with patch.dict(os.environ, {'TEST_VAR': 'test_value'}):
            data = {'key': '{$TEST_VAR}'}
            result = load_env_vars(data)
            assert result['key'] == 'test_value'
    
    def test_load_env_vars_with_default(self):
        """Test load_env_vars with default value."""
        data = {'key': '{$MISSING_VAR:default_value}'}
        result = load_env_vars(data)
        assert result['key'] == 'default_value'
    
    def test_load_env_vars_with_empty_default(self):
        """Test load_env_vars with empty default."""
        data = {'key': '{$MISSING_VAR:}'}
        result = load_env_vars(data)
        assert result['key'] == ''
    
    def test_load_env_vars_embedded_in_string(self):
        """Test load_env_vars with embedded variables."""
        with patch.dict(os.environ, {'HOST': 'localhost', 'PORT': '8000'}):
            data = {'url': 'http://{$HOST}:{$PORT}/api'}
            result = load_env_vars(data)
            assert result['url'] == 'http://localhost:8000/api'
    
    def test_load_env_vars_nested_dict(self):
        """Test load_env_vars with nested dictionary."""
        with patch.dict(os.environ, {'TEST_VAR': 'nested_value'}):
            data = {
                'level1': {
                    'level2': {
                        'key': '{$TEST_VAR}'
                    }
                }
            }
            result = load_env_vars(data)
            assert result['level1']['level2']['key'] == 'nested_value'
    
    def test_load_env_vars_nested_list(self):
        """Test load_env_vars with nested list."""
        with patch.dict(os.environ, {'TEST_VAR': 'list_value'}):
            data = {
                'items': [
                    '{$TEST_VAR}',
                    'static_value'
                ]
            }
            result = load_env_vars(data)
            assert result['items'][0] == 'list_value'
            assert result['items'][1] == 'static_value'
    
    def test_load_env_vars_missing_var_no_default(self):
        """Test load_env_vars with missing variable and no default."""
        with patch('builtins.print'):
            data = {'key': '{$MISSING_VAR}'}
            result = load_env_vars(data)
            assert 'Undefined variable' in result['key']
    
    def test_load_env_vars_string_direct(self):
        """Test load_env_vars with string directly."""
        with patch.dict(os.environ, {'TEST_VAR': 'direct_value'}):
            result = load_env_vars('{$TEST_VAR}')
            assert result == 'direct_value'
    
    def test_load_env_vars_max_depth(self):
        """Test load_env_vars with max depth limit."""
        # Create deeply nested structure
        data = {'level': {}}
        current = data['level']
        for i in range(150):  # More than MAX_RECURSION_DEPTH
            current['level'] = {}
            current = current['level']
        
        # Should not raise exception
        result = load_env_vars(data)
        assert result is not None
    
    def test_load_env_vars_circular_reference(self):
        """Test load_env_vars with circular reference."""
        data = {}
        data['self'] = data  # Circular reference
        
        # Should not raise exception
        result = load_env_vars(data)
        assert result is not None


class TestSaveToDisk:
    """Test save_to_disk() - legacy function."""
    
    @pytest.mark.asyncio
    async def test_save_to_disk_default_path(self):
        """Test save_to_disk with default path."""
        config = {'module-config': {}}
        payload = {'data': 'test'}
        
        with patch('os.path.exists', return_value=False), \
             patch('os.makedirs'), \
             patch('builtins.open', mock_open()) as mock_file:
            
            await save_to_disk(payload, config)
            
            mock_file.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_save_to_disk_custom_path(self):
        """Test save_to_disk with custom path."""
        config = {'module-config': {'path': '/tmp/webhooks'}}
        payload = {'data': 'test'}
        
        with patch('os.path.exists', return_value=False), \
             patch('os.makedirs') as mock_makedirs, \
             patch('builtins.open', mock_open()) as mock_file:
            
            await save_to_disk(payload, config)
            
            mock_makedirs.assert_called_once_with('/tmp/webhooks')
            mock_file.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_save_to_disk_path_exists(self):
        """Test save_to_disk when path already exists."""
        config = {'module-config': {'path': '/tmp/webhooks'}}
        payload = {'data': 'test'}
        
        with patch('os.path.exists', return_value=True), \
             patch('builtins.open', mock_open()) as mock_file:
            
            await save_to_disk(payload, config)
            
            mock_file.assert_called_once()


class TestPrintToStdout:
    """Test print_to_stdout() - legacy function."""
    
    @pytest.mark.asyncio
    async def test_print_to_stdout(self):
        """Test print_to_stdout function."""
        payload = {'data': 'test'}
        headers = {'Content-Type': 'application/json'}
        config = {'module': 'log'}
        
        with patch('builtins.print') as mock_print:
            await print_to_stdout(payload, headers, config)
            
            assert mock_print.call_count == 3


class TestEndpointStats:
    """Test EndpointStats class."""
    
    @pytest.mark.asyncio
    async def test_increment(self):
        """Test increment method."""
        stats = EndpointStats()
        
        await stats.increment('test_endpoint')
        
        result = stats.get_stats()
        assert 'test_endpoint' in result
        assert result['test_endpoint']['total'] == 1
    
    @pytest.mark.asyncio
    async def test_increment_multiple(self):
        """Test increment multiple times."""
        stats = EndpointStats()
        
        for _ in range(5):
            await stats.increment('test_endpoint')
        
        result = stats.get_stats()
        assert result['test_endpoint']['total'] == 5
    
    @pytest.mark.asyncio
    async def test_get_stats_all_windows(self):
        """Test get_stats with all time windows."""
        stats = EndpointStats()
        
        # Increment multiple times
        for _ in range(10):
            await stats.increment('test_endpoint')
        
        result = stats.get_stats()
        endpoint_stats = result['test_endpoint']
        
        assert 'total' in endpoint_stats
        assert 'minute' in endpoint_stats
        assert '5_minutes' in endpoint_stats
        assert '15_minutes' in endpoint_stats
        assert '30_minutes' in endpoint_stats
        assert 'hour' in endpoint_stats
        assert 'day' in endpoint_stats
        assert 'week' in endpoint_stats
        assert 'month' in endpoint_stats
    
    @pytest.mark.asyncio
    async def test_cleanup_old_buckets(self):
        """Test _cleanup_old_buckets method."""
        stats = EndpointStats()
        
        # Add some old buckets
        old_time = datetime.now(timezone.utc) - timedelta(days=2)
        stats.timestamps['test_endpoint'][old_time] = 5
        
        # Add recent bucket
        recent_time = datetime.now(timezone.utc)
        stats.timestamps['test_endpoint'][recent_time] = 10
        
        # Increment should trigger cleanup
        await stats.increment('test_endpoint')
        
        # Old bucket should be removed
        assert old_time not in stats.timestamps['test_endpoint']
        assert recent_time in stats.timestamps['test_endpoint']
    
    @pytest.mark.asyncio
    async def test_increment_invalid_endpoint_name(self):
        """Test increment with invalid endpoint name."""
        stats = EndpointStats()
        
        with pytest.raises((TypeError, ValueError)):
            await stats.increment(None)
    
    @pytest.mark.asyncio
    async def test_increment_too_long_endpoint_name(self):
        """Test increment with too long endpoint name."""
        stats = EndpointStats()
        
        long_name = "a" * 300
        with pytest.raises(ValueError, match="too long"):
            await stats.increment(long_name)
    
    @pytest.mark.asyncio
    async def test_increment_with_null_byte(self):
        """Test increment with null byte in endpoint name."""
        stats = EndpointStats()
        
        with pytest.raises(ValueError, match="null byte"):
            await stats.increment("endpoint\x00name")


class TestRedisEndpointStats:
    """Test RedisEndpointStats class."""
    
    @pytest.mark.asyncio
    async def test_reconnect_if_needed_no_connection(self):
        """Test _reconnect_if_needed when no connection exists."""
        stats = RedisEndpointStats()
        stats._redis = None
        
        with patch('redis.asyncio.from_url', return_value=AsyncMock()) as mock_redis:
            await stats._reconnect_if_needed()
            
            assert stats._redis is not None
            mock_redis.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_reconnect_if_needed_valid_connection(self):
        """Test _reconnect_if_needed with valid connection."""
        stats = RedisEndpointStats()
        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock()
        stats._redis = mock_redis
        
        await stats._reconnect_if_needed()
        
        mock_redis.ping.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_reconnect_if_needed_invalid_connection(self):
        """Test _reconnect_if_needed with invalid connection."""
        stats = RedisEndpointStats()
        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(side_effect=RuntimeError("Connection closed"))
        mock_redis.aclose = AsyncMock()
        stats._redis = mock_redis
        
        with patch('redis.asyncio.from_url', return_value=AsyncMock()) as mock_new_redis:
            await stats._reconnect_if_needed()
            
            mock_redis.aclose.assert_called_once()
            assert stats._redis is not None
    
    @pytest.mark.asyncio
    async def test_increment_multi_resolution_success(self):
        """Test increment_multi_resolution successful increment."""
        stats = RedisEndpointStats()
        mock_redis = AsyncMock()
        mock_pipe = AsyncMock()
        mock_pipe.__aenter__ = AsyncMock(return_value=mock_pipe)
        mock_pipe.__aexit__ = AsyncMock()
        mock_pipe.execute = AsyncMock()
        mock_redis.pipeline = Mock(return_value=mock_pipe)
        stats._redis = mock_redis
        
        await stats.increment_multi_resolution('test_endpoint')
        
        mock_pipe.execute.assert_called_once()
    
    @pytest.mark.todo
    @pytest.mark.asyncio
    async def test_increment_multi_resolution_retry(self):
        """Test increment_multi_resolution with retry."""
        stats = RedisEndpointStats()
        mock_redis = AsyncMock()
        mock_pipe = AsyncMock()
        mock_pipe.__aenter__ = AsyncMock(return_value=mock_pipe)
        mock_pipe.__aexit__ = AsyncMock()
        mock_pipe.execute = AsyncMock(side_effect=[RuntimeError("Connection error"), None])
        mock_redis.pipeline = Mock(return_value=mock_pipe)
        stats._redis = mock_redis
        
        with patch.object(stats, '_reconnect_if_needed', return_value=None):
            await stats.increment_multi_resolution('test_endpoint')
            
            assert mock_pipe.execute.call_count == 2
    
    @pytest.mark.asyncio
    async def test_increment_multi_resolution_invalid_name(self):
        """Test increment_multi_resolution with invalid endpoint name."""
        stats = RedisEndpointStats()
        
        with pytest.raises(ValueError):
            await stats.increment_multi_resolution(None)
    
    @pytest.mark.asyncio
    async def test_increment_multi_resolution_empty_name(self):
        """Test increment_multi_resolution with empty name."""
        stats = RedisEndpointStats()
        
        with pytest.raises(ValueError):
            await stats.increment_multi_resolution("   ")
    
    @pytest.mark.asyncio
    async def test_increment_multi_resolution_too_long(self):
        """Test increment_multi_resolution with too long name."""
        stats = RedisEndpointStats()
        
        long_name = "a" * 300
        with pytest.raises(ValueError, match="too long"):
            await stats.increment_multi_resolution(long_name)
    
    @pytest.mark.asyncio
    async def test_increment_multi_resolution_with_newline(self):
        """Test increment_multi_resolution with newline in name."""
        stats = RedisEndpointStats()
        
        with pytest.raises(ValueError, match="newlines"):
            await stats.increment_multi_resolution("endpoint\nname")
    
    @pytest.mark.asyncio
    async def test_get_stats_optimized(self):
        """Test _get_stats_optimized method."""
        stats = RedisEndpointStats()
        mock_redis = AsyncMock()
        mock_redis.smembers = AsyncMock(return_value={'endpoint1', 'endpoint2'})
        mock_redis.get = AsyncMock(return_value='100')
        mock_redis.mget = AsyncMock(return_value=['10', '20', '30'])
        stats._redis = mock_redis
        
        result = await stats._get_stats_optimized()
        
        assert 'endpoint1' in result
        assert 'endpoint2' in result
        assert result['endpoint1']['total'] == 100
    
    @pytest.mark.asyncio
    async def test_get_stats_optimized_invalid_endpoint(self):
        """Test _get_stats_optimized with invalid endpoint names."""
        stats = RedisEndpointStats()
        mock_redis = AsyncMock()
        # Include invalid endpoints
        mock_redis.smembers = AsyncMock(return_value={
            'valid_endpoint',
            None,  # Invalid
            'a' * 300,  # Too long
            'endpoint\nname'  # Has newline
        })
        mock_redis.get = AsyncMock(return_value='100')
        mock_redis.mget = AsyncMock(return_value=[])
        stats._redis = mock_redis
        
        result = await stats._get_stats_optimized()
        
        # Only valid endpoint should be in result
        assert 'valid_endpoint' in result
        assert None not in result
    
    @pytest.mark.todo
    @pytest.mark.asyncio
    async def test_get_stats_optimized_connection_error(self):
        """Test _get_stats_optimized with connection error."""
        stats = RedisEndpointStats()
        mock_redis = AsyncMock()
        mock_redis.smembers = AsyncMock(side_effect=[RuntimeError("Connection error"), {'endpoint1'}])
        stats._redis = mock_redis
        
        with patch.object(stats, '_reconnect_if_needed', return_value=None):
            result = await stats._get_stats_optimized()
            
            assert mock_redis.smembers.call_count == 2
    
    @pytest.mark.asyncio
    async def test_cleanup_old_buckets(self):
        """Test _cleanup_old_buckets (should be no-op for Redis)."""
        stats = RedisEndpointStats()
        
        # Should not raise exception
        await stats._cleanup_old_buckets('test_endpoint', int(time.time()))


class TestCredentialCleaner:
    """Test CredentialCleaner class."""
    
    def test_init_mask_mode(self):
        """Test CredentialCleaner initialization with mask mode."""
        cleaner = CredentialCleaner(mode='mask')
        assert cleaner.mode == 'mask'
    
    def test_init_remove_mode(self):
        """Test CredentialCleaner initialization with remove mode."""
        cleaner = CredentialCleaner(mode='remove')
        assert cleaner.mode == 'remove'
    
    def test_init_invalid_mode(self):
        """Test CredentialCleaner initialization with invalid mode."""
        with pytest.raises(ValueError, match="must be 'mask' or 'remove'"):
            CredentialCleaner(mode='invalid')
    
    def test_init_with_custom_fields(self):
        """Test CredentialCleaner initialization with custom fields."""
        cleaner = CredentialCleaner(custom_fields=['custom_secret', 'api_token'])
        assert 'custom_secret' in cleaner.credential_fields
        assert 'api_token' in cleaner.credential_fields
    
    def test_init_invalid_custom_fields(self):
        """Test CredentialCleaner initialization with invalid custom_fields."""
        with pytest.raises(TypeError):
            CredentialCleaner(custom_fields="not a list")
    
    def test_clean_credentials_dict_mask_mode(self):
        """Test clean_credentials with dict in mask mode."""
        cleaner = CredentialCleaner(mode='mask')
        data = {
            'username': 'user123',
            'password': 'secret123',
            'api_key': 'key456'
        }
        
        result = cleaner.clean_credentials(data)
        
        assert result['username'] == 'user123'
        assert result['password'] == '***REDACTED***'
        assert result['api_key'] == '***REDACTED***'
    
    def test_clean_credentials_dict_remove_mode(self):
        """Test clean_credentials with dict in remove mode."""
        cleaner = CredentialCleaner(mode='remove')
        data = {
            'username': 'user123',
            'password': 'secret123',
            'api_key': 'key456'
        }
        
        result = cleaner.clean_credentials(data)
        
        assert result['username'] == 'user123'
        assert 'password' not in result
        assert 'api_key' not in result
    
    def test_clean_credentials_nested_dict(self):
        """Test clean_credentials with nested dictionary."""
        cleaner = CredentialCleaner(mode='mask')
        data = {
            'user': {
                'email': 'user@example.com',
                'password': 'secret123',
                'nested': {
                    'token': 'token789'
                }
            }
        }
        
        result = cleaner.clean_credentials(data)
        
        assert result['user']['email'] == 'user@example.com'
        assert result['user']['password'] == '***REDACTED***'
        assert result['user']['nested']['token'] == '***REDACTED***'
    
    def test_clean_credentials_list(self):
        """Test clean_credentials with list."""
        cleaner = CredentialCleaner(mode='mask')
        data = [
            {'username': 'user1', 'password': 'pass1'},
            {'username': 'user2', 'password': 'pass2'}
        ]
        
        result = cleaner.clean_credentials(data)
        
        assert result[0]['username'] == 'user1'
        assert result[0]['password'] == '***REDACTED***'
    
    def test_clean_credentials_circular_reference(self):
        """Test clean_credentials with circular reference."""
        cleaner = CredentialCleaner(mode='mask')
        data = {}
        data['self'] = data  # Circular reference
        
        # Should not raise exception
        result = cleaner.clean_credentials(data)
        assert result is not None
    
    def test_clean_credentials_max_depth(self):
        """Test clean_credentials with max depth."""
        cleaner = CredentialCleaner(mode='mask')
        # Create deeply nested structure
        data = {'level': {}}
        current = data['level']
        for i in range(150):  # More than MAX_RECURSION_DEPTH
            current['level'] = {}
            current = current['level']
        
        # Should not raise exception
        result = cleaner.clean_credentials(data)
        assert result is not None
    
    def test_clean_credentials_none(self):
        """Test clean_credentials with None."""
        cleaner = CredentialCleaner(mode='mask')
        result = cleaner.clean_credentials(None)
        assert result is None
    
    def test_clean_headers_mask_mode(self):
        """Test clean_headers in mask mode."""
        cleaner = CredentialCleaner(mode='mask')
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer token123',
            'X-API-Key': 'key456'
        }
        
        result = cleaner.clean_headers(headers)
        
        assert result['Content-Type'] == 'application/json'
        assert result['Authorization'] == '***REDACTED***'
        assert result['X-API-Key'] == '***REDACTED***'
    
    def test_clean_headers_remove_mode(self):
        """Test clean_headers in remove mode."""
        cleaner = CredentialCleaner(mode='remove')
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer token123',
            'X-API-Key': 'key456'
        }
        
        result = cleaner.clean_headers(headers)
        
        assert result['Content-Type'] == 'application/json'
        assert 'Authorization' not in result
        assert 'X-API-Key' not in result
    
    def test_clean_headers_none(self):
        """Test clean_headers with None."""
        cleaner = CredentialCleaner(mode='mask')
        result = cleaner.clean_headers(None)
        assert result == {}
    
    def test_clean_headers_not_dict(self):
        """Test clean_headers with non-dict."""
        cleaner = CredentialCleaner(mode='mask')
        result = cleaner.clean_headers("not a dict")
        assert result == {}
    
    def test_clean_query_params_mask_mode(self):
        """Test clean_query_params in mask mode."""
        cleaner = CredentialCleaner(mode='mask')
        params = {
            'action': 'create',
            'api_key': 'key123',
            'token': 'token456'
        }
        
        result = cleaner.clean_query_params(params)
        
        assert result['action'] == 'create'
        assert result['api_key'] == '***REDACTED***'
        assert result['token'] == '***REDACTED***'
    
    def test_clean_query_params_remove_mode(self):
        """Test clean_query_params in remove mode."""
        cleaner = CredentialCleaner(mode='remove')
        params = {
            'action': 'create',
            'api_key': 'key123',
            'token': 'token456'
        }
        
        result = cleaner.clean_query_params(params)
        
        assert result['action'] == 'create'
        assert 'api_key' not in result
        assert 'token' not in result
    
    def test_clean_query_params_none(self):
        """Test clean_query_params with None."""
        cleaner = CredentialCleaner(mode='mask')
        result = cleaner.clean_query_params(None)
        assert result == {}
    
    def test_clean_query_params_not_dict(self):
        """Test clean_query_params with non-dict."""
        cleaner = CredentialCleaner(mode='mask')
        result = cleaner.clean_query_params("not a dict")
        assert result == {}
    
    def test_clean_dict_recursive_credential_in_container(self):
        """Test _clean_dict_recursive with credential field containing container."""
        cleaner = CredentialCleaner(mode='mask')
        data = {
            'password': {
                'hash': 'hash123',
                'salt': 'salt456'
            }
        }
        
        result = cleaner._clean_dict_recursive(data)
        
        # Container should be processed recursively
        assert isinstance(result['password'], dict)
        assert 'hash' in result['password']
        assert 'salt' in result['password']

