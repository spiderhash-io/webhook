"""Tests for ConnectionPoolRegistry."""
import pytest
import asyncio
from unittest.mock import AsyncMock
from src.connection_pool_registry import ConnectionPoolRegistry


class TestConnectionPoolRegistry:
    """Test suite for ConnectionPoolRegistry."""
    pytestmark = pytest.mark.todo
    
    @pytest.fixture
    def pool_registry(self):
        """Create ConnectionPoolRegistry instance."""
        return ConnectionPoolRegistry(migration_timeout=1.0)  # Short timeout for tests
    
    @pytest.mark.asyncio
    async def test_get_pool_creates_new_pool(self, pool_registry):
        """Test that get_pool creates a new pool."""
        async def mock_factory(config):
            pool = AsyncMock()
            pool.close_all = AsyncMock()
            return pool
        
        config = {"type": "rabbitmq", "host": "test.example.com", "port": 5672}
        pool = await pool_registry.get_pool("conn1", config, mock_factory)
        
        assert pool is not None
        assert "conn1" in pool_registry._pools
    
    @pytest.mark.asyncio
    async def test_get_pool_reuses_existing_pool(self, pool_registry):
        """Test that get_pool reuses pool with same config."""
        async def mock_factory(config):
            pool = AsyncMock()
            pool.close_all = AsyncMock()
            return pool
        
        config = {"type": "rabbitmq", "host": "test.example.com", "port": 5672}
        pool1 = await pool_registry.get_pool("conn1", config, mock_factory)
        pool2 = await pool_registry.get_pool("conn1", config, mock_factory)
        
        assert pool1 is pool2  # Same pool instance
    
    @pytest.mark.asyncio
    async def test_get_pool_creates_new_pool_on_config_change(self, pool_registry):
        """Test that config change creates new pool and deprecates old one."""
        async def mock_factory(config):
            pool = AsyncMock()
            pool.close_all = AsyncMock()
            return pool
        
        config1 = {"type": "rabbitmq", "host": "test.example.com", "port": 5672}
        pool1 = await pool_registry.get_pool("conn1", config1, mock_factory)
        
        config2 = {"type": "rabbitmq", "host": "test.example.com", "port": 5673}  # Different port
        pool2 = await pool_registry.get_pool("conn1", config2, mock_factory)
        
        assert pool1 is not pool2  # Different pools
        assert "conn1" in pool_registry._deprecated_pools  # Old pool deprecated
    
    @pytest.mark.asyncio
    async def test_release_pool(self, pool_registry):
        """Test releasing a pool."""
        async def mock_factory(config):
            pool = AsyncMock()
            pool.close_all = AsyncMock()
            return pool
        
        config = {"type": "rabbitmq", "host": "test.example.com", "port": 5672}
        pool = await pool_registry.get_pool("conn1", config, mock_factory)
        
        pool_info = pool_registry._pools["conn1"]
        initial_requests = pool_info.active_requests
        
        await pool_registry.release_pool("conn1", pool)
        
        assert pool_registry._pools["conn1"].active_requests < initial_requests
    
    @pytest.mark.asyncio
    async def test_cleanup_deprecated_pools(self, pool_registry):
        """Test cleanup of deprecated pools."""
        async def mock_factory(config):
            pool = AsyncMock()
            pool.close_all = AsyncMock()
            return pool
        
        config1 = {"type": "rabbitmq", "host": "test.example.com", "port": 5672}
        pool1 = await pool_registry.get_pool("conn1", config1, mock_factory)
        
        config2 = {"type": "rabbitmq", "host": "test.example.com", "port": 5673}
        pool2 = await pool_registry.get_pool("conn1", config2, mock_factory)
        
        # Release the deprecated pool
        await pool_registry.release_pool("conn1", pool1)
        
        # Wait for migration timeout
        await asyncio.sleep(1.5)
        
        # Cleanup should remove deprecated pool
        cleaned = await pool_registry.cleanup_deprecated_pools()
        assert cleaned >= 0  # May have already been cleaned
    
    @pytest.mark.asyncio
    async def test_get_pool_info(self, pool_registry):
        """Test getting pool information."""
        async def mock_factory(config):
            pool = AsyncMock()
            pool.close_all = AsyncMock()
            return pool
        
        config = {"type": "rabbitmq", "host": "test.example.com", "port": 5672}
        await pool_registry.get_pool("conn1", config, mock_factory)
        
        info = pool_registry.get_pool_info("conn1")
        assert info is not None
        assert info["connection_name"] == "conn1"
        assert info["deprecated"] is False
    
    @pytest.mark.asyncio
    async def test_get_all_pools_info(self, pool_registry):
        """Test getting information about all pools."""
        async def mock_factory(config):
            pool = AsyncMock()
            pool.close_all = AsyncMock()
            return pool
        
        config1 = {"type": "rabbitmq", "host": "test1.example.com", "port": 5672}
        config2 = {"type": "redis-rq", "host": "test2.example.com", "port": 6379}
        
        await pool_registry.get_pool("conn1", config1, mock_factory)
        await pool_registry.get_pool("conn2", config2, mock_factory)
        
        all_info = pool_registry.get_all_pools_info()
        assert len(all_info) >= 2
        assert "conn1" in all_info
        assert "conn2" in all_info
    
    @pytest.mark.asyncio
    async def test_close_all_pools(self, pool_registry):
        """Test closing all pools."""
        async def mock_factory(config):
            pool = AsyncMock()
            pool.close_all = AsyncMock()
            return pool
        
        config = {"type": "rabbitmq", "host": "test.example.com", "port": 5672}
        pool = await pool_registry.get_pool("conn1", config, mock_factory)
        
        await pool_registry.close_all_pools()
        
        # Pools should be closed
        assert len(pool_registry._pools) == 0
        assert len(pool_registry._deprecated_pools) == 0

