"""
Integration tests for connection_pool_registry.py.
Tests cover missing coverage areas including error handling, deprecated pool cleanup, and pool info operations.
"""
import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock

from src.connection_pool_registry import ConnectionPoolRegistry, PoolInfo


class TestConnectionPoolRegistryErrorHandling:
    """Test error handling in connection pool registry."""
    
    @pytest.mark.asyncio
    async def test_get_pool_with_factory_error(self):
        """Test get_pool when factory function raises error."""
        registry = ConnectionPoolRegistry()
        
        async def failing_factory(connection_name, connection_config):
            raise Exception("Factory failed")
        
        connection_config = {'type': 'test', 'host': 'localhost'}
        
        with pytest.raises(RuntimeError, match="Failed to create connection pool"):
            await registry.get_pool('test_conn', connection_config, failing_factory)
    
    @pytest.mark.asyncio
    async def test_get_pool_with_invalid_config(self):
        """Test get_pool with invalid connection config (circular reference)."""
        registry = ConnectionPoolRegistry()
        
        # Create config with circular reference
        circular_config = {'type': 'test'}
        circular_config['self'] = circular_config
        
        async def factory(name, config):
            return Mock()
        
        with pytest.raises(ValueError, match="Invalid connection_config"):
            await registry.get_pool('test_conn', circular_config, factory)


class TestConnectionPoolRegistryDeprecatedPools:
    """Test deprecated pool cleanup."""
    
    @pytest.mark.asyncio
    async def test_cleanup_deprecated_pools(self):
        """Test cleanup of deprecated pools."""
        import time
        registry = ConnectionPoolRegistry()
        
        # Create a deprecated pool that's old enough to be cleaned up
        mock_pool = AsyncMock()
        mock_pool.close = AsyncMock()
        
        pool_info = PoolInfo(
            connection_name='test_conn',
            pool=mock_pool,
            config_hash='old_hash',
            created_at=time.time(),
            deprecated_at=time.time() - registry.migration_timeout - 1  # Old enough
        )
        registry._deprecated_pools['test_conn'] = pool_info
        
        await registry.cleanup_deprecated_pools()
        
        mock_pool.close.assert_called_once()
        assert 'test_conn' not in registry._deprecated_pools
    
    @pytest.mark.asyncio
    async def test_cleanup_deprecated_pools_with_error(self):
        """Test cleanup of deprecated pools with error."""
        import time
        registry = ConnectionPoolRegistry()
        
        # Create a deprecated pool that fails to close
        mock_pool = AsyncMock()
        mock_pool.close = AsyncMock(side_effect=Exception("Close failed"))
        
        pool_info = PoolInfo(
            connection_name='test_conn',
            pool=mock_pool,
            config_hash='old_hash',
            created_at=time.time(),
            deprecated_at=time.time() - registry.migration_timeout - 1  # Old enough
        )
        registry._deprecated_pools['test_conn'] = pool_info
        
        # Should handle error gracefully
        await registry.cleanup_deprecated_pools()
        
        mock_pool.close.assert_called_once()
        # Pool should still be removed even on error
        assert 'test_conn' not in registry._deprecated_pools


class TestConnectionPoolRegistryGetAllPoolInfo:
    """Test get_all_pool_info method."""
    
    def test_get_all_pool_info_with_pools(self):
        """Test get_all_pool_info with active and deprecated pools."""
        import time
        registry = ConnectionPoolRegistry()
        
        # Add active pool
        mock_pool1 = Mock()
        pool_info1 = PoolInfo(
            connection_name='active_conn',
            pool=mock_pool1,
            config_hash='hash1',
            created_at=time.time()
        )
        registry._pools['active_conn'] = pool_info1
        
        # Add deprecated pool
        mock_pool2 = Mock()
        pool_info2 = PoolInfo(
            connection_name='deprecated_conn',
            pool=mock_pool2,
            config_hash='hash2',
            created_at=time.time(),
            deprecated_at=time.time()
        )
        registry._deprecated_pools['deprecated_conn'] = pool_info2
        
        result = registry.get_all_pools_info()
        
        assert 'active_conn' in result
        assert 'deprecated_conn' in result
    
    def test_get_all_pool_info_empty(self):
        """Test get_all_pool_info with no pools."""
        registry = ConnectionPoolRegistry()
        
        result = registry.get_all_pools_info()
        
        assert result == {}


class TestConnectionPoolRegistryCloseAllPools:
    """Test close_all_pools method."""
    
    @pytest.mark.asyncio
    async def test_close_all_pools_success(self):
        """Test closing all pools successfully."""
        registry = ConnectionPoolRegistry()
        
        # Add pools
        mock_pool1 = AsyncMock()
        mock_pool1.close = AsyncMock()
        pool_info1 = PoolInfo(
            connection_name='conn1',
            pool=mock_pool1,
            config_hash='hash1',
            created_at=None
        )
        registry._pools['conn1'] = pool_info1
        
        mock_pool2 = AsyncMock()
        mock_pool2.close = AsyncMock()
        pool_info2 = PoolInfo(
            connection_name='conn2',
            pool=mock_pool2,
            config_hash='hash2',
            created_at=None
        )
        registry._pools['conn2'] = pool_info2
        
        await registry.close_all_pools()
        
        mock_pool1.close.assert_called_once()
        mock_pool2.close.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_close_all_pools_with_error(self):
        """Test closing all pools with some errors."""
        registry = ConnectionPoolRegistry()
        
        # Add pool that fails to close
        mock_pool = AsyncMock()
        mock_pool.close = AsyncMock(side_effect=Exception("Close failed"))
        pool_info = PoolInfo(
            connection_name='conn1',
            pool=mock_pool,
            config_hash='hash1',
            created_at=None
        )
        registry._pools['conn1'] = pool_info
        
        # Should handle error gracefully
        await registry.close_all_pools()
        
        mock_pool.close.assert_called_once()


class TestConnectionPoolRegistryGetPoolInfo:
    """Test get_pool_info method."""
    
    def test_get_pool_info_active_pool(self):
        """Test getting info for active pool."""
        import time
        registry = ConnectionPoolRegistry()
        
        mock_pool = Mock()
        pool_info = PoolInfo(
            connection_name='test_conn',
            pool=mock_pool,
            config_hash='hash1',
            created_at=time.time()
        )
        registry._pools['test_conn'] = pool_info
        
        result = registry.get_pool_info('test_conn')
        
        assert result is not None
        assert result['connection_name'] == 'test_conn'
    
    def test_get_pool_info_deprecated_pool(self):
        """Test getting info for deprecated pool."""
        import time
        registry = ConnectionPoolRegistry()
        
        mock_pool = Mock()
        pool_info = PoolInfo(
            connection_name='test_conn',
            pool=mock_pool,
            config_hash='hash1',
            created_at=time.time(),
            deprecated_at=time.time()
        )
        registry._deprecated_pools['test_conn'] = pool_info
        
        result = registry.get_pool_info('test_conn')
        
        assert result is not None
        assert result['connection_name'] == 'test_conn'
        assert result['deprecated'] is True
    
    def test_get_pool_info_nonexistent(self):
        """Test getting info for non-existent pool."""
        registry = ConnectionPoolRegistry()
        
        result = registry.get_pool_info('nonexistent')
        
        assert result is None

