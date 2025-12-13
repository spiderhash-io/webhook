"""
Integration tests for redis_rq.py module.
Tests cover missing coverage areas including error handling and edge cases.
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock

from src.modules.redis_rq import RedisRQModule


class TestRedisRQModuleErrorHandling:
    """Test error handling in Redis RQ module."""
    
    @pytest.mark.asyncio
    async def test_process_without_connection(self):
        """Test process without connection."""
        config = {
            'module-config': {
                'function': 'test_module.test_function'
            },
            'connection_details': {}  # No 'conn' key
        }
        
        module = RedisRQModule(config)
        
        with pytest.raises(Exception, match="Redis connection is not defined"):
            await module.process({'data': 'test'}, {})
    
    @pytest.mark.asyncio
    async def test_process_with_enqueue_error(self):
        """Test process when enqueue fails."""
        config = {
            'module-config': {
                'function_name': 'test_module.test_function'
            },
            'connection_details': {}
        }
        
        module = RedisRQModule(config)
        
        mock_connection = Mock()
        mock_queue = Mock()
        mock_queue.enqueue = Mock(side_effect=Exception("Enqueue failed"))
        mock_connection.default_queue = mock_queue
        module.connection = mock_connection
        
        with pytest.raises(Exception):
            await module.process({'data': 'test'}, {})
    
    @pytest.mark.asyncio
    async def test_process_with_custom_queue(self):
        """Test process with custom queue name."""
        from rq import Queue
        
        config = {
            'module-config': {
                'function': 'test_module.test_function',
                'queue_name': 'custom_queue'
            },
            'connection_details': {
                'conn': Mock()  # Redis connection object
            }
        }
        
        module = RedisRQModule(config)
        
        mock_connection = config['connection_details']['conn']
        
        with patch('src.modules.redis_rq.Queue') as mock_queue_class:
            mock_queue = Mock()
            mock_queue.enqueue = Mock(return_value=Mock(id='test-id'))
            mock_queue_class.return_value = mock_queue
            
            await module.process({'data': 'test'}, {})
            
            mock_queue_class.assert_called_once_with('custom_queue', connection=mock_connection)
            mock_queue.enqueue.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_process_with_default_queue(self):
        """Test process with default queue."""
        from rq import Queue
        
        config = {
            'module-config': {
                'function': 'test_module.test_function'
            },
            'connection_details': {
                'conn': Mock()  # Redis connection object
            }
        }
        
        module = RedisRQModule(config)
        
        mock_connection = config['connection_details']['conn']
        
        with patch('src.modules.redis_rq.Queue') as mock_queue_class:
            mock_queue = Mock()
            mock_queue.enqueue = Mock(return_value=Mock(id='test-id'))
            mock_queue_class.return_value = mock_queue
            
            await module.process({'data': 'test'}, {})
            
            mock_queue_class.assert_called_once_with('default', connection=mock_connection)
            mock_queue.enqueue.assert_called_once()


class TestRedisRQModuleFunctionNameValidation:
    """Test function name validation edge cases."""
    
    def test_init_with_valid_function_name(self):
        """Test initialization with valid function name."""
        config = {
            'module-config': {
                'function': 'test_module.test_function'  # Note: key is 'function', not 'function_name'
            },
            'connection_details': {}
        }
        
        module = RedisRQModule(config)
        
        assert module._validated_function_name == 'test_module.test_function'
    
    def test_init_without_function_name(self):
        """Test initialization without function name."""
        config = {
            'module-config': {},
            'connection_details': {}
        }
        
        module = RedisRQModule(config)
        
        assert module._validated_function_name is None
    
    @pytest.mark.asyncio
    async def test_process_without_function_name(self):
        """Test process without function name."""
        config = {
            'module-config': {},
            'connection_details': {'conn': Mock()}
        }
        
        module = RedisRQModule(config)
        
        with pytest.raises(Exception, match="Function name not specified"):
            await module.process({'data': 'test'}, {})

