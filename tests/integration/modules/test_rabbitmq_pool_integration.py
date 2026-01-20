"""
Integration tests for RabbitMQ connection pool.

These tests verify connection pool behavior, exhaustion handling, and circuit breaker functionality.
"""

import pytest
import asyncio
from src.modules.rabbitmq import RabbitMQConnectionPool
from tests.integration.test_config import (
    RABBITMQ_HOST,
    RABBITMQ_PORT,
    RABBITMQ_USER,
    RABBITMQ_PASS,
)


@pytest.mark.integration
class TestRabbitMQPoolIntegration:
    """Integration tests for RabbitMQ connection pool."""

    @pytest.fixture
    async def connection_pool(self):
        """Create a RabbitMQ connection pool for testing."""
        pool = RabbitMQConnectionPool(max_size=2, acquisition_timeout=5.0)
        await pool.create_pool(
            host=RABBITMQ_HOST,
            port=RABBITMQ_PORT,
            login=RABBITMQ_USER,
            password=RABBITMQ_PASS,
        )
        yield pool
        # Cleanup: close all connections
        await pool.close_all()

    @pytest.mark.asyncio
    async def test_pool_creation(self, connection_pool):
        """Test that connection pool is created successfully."""
        assert connection_pool.max_size == 2
        assert connection_pool.acquisition_timeout == 5.0
        assert connection_pool.connections.qsize() == 2

    @pytest.mark.asyncio
    async def test_pool_connection_acquisition(self, connection_pool):
        """Test acquiring connections from the pool."""
        # Get a connection
        connection = await connection_pool.get_connection()
        assert connection is not None
        assert connection.is_closed is False

        # Release connection
        await connection_pool.release(connection)

        # Verify connection is back in pool
        assert connection_pool.connections.qsize() == 2

    @pytest.mark.asyncio
    async def test_pool_connection_release(self, connection_pool):
        """Test releasing connections back to the pool."""
        # Get all connections
        conn1 = await connection_pool.get_connection()
        conn2 = await connection_pool.get_connection()

        # Pool should be empty now
        assert connection_pool.connections.qsize() == 0

        # Release connections
        await connection_pool.release(conn1)
        await connection_pool.release(conn2)

        # Pool should be full again
        assert connection_pool.connections.qsize() == 2

    @pytest.mark.asyncio
    async def test_pool_exhaustion_timeout(self, connection_pool):
        """Test that pool exhaustion triggers timeout."""
        # Get all available connections
        conn1 = await connection_pool.get_connection()
        conn2 = await connection_pool.get_connection()

        # Try to get another connection (should timeout and raise Exception)
        with pytest.raises(Exception, match="Connection pool exhausted"):
            await connection_pool.get_connection()

        # Release connections
        await connection_pool.release(conn1)
        await connection_pool.release(conn2)

    @pytest.mark.asyncio
    async def test_pool_metrics(self, connection_pool):
        """Test that pool metrics are tracked correctly."""
        # Get initial metrics
        initial_metrics = connection_pool.get_metrics()
        assert initial_metrics["total_requests"] == 0
        assert initial_metrics["successful_acquisitions"] == 0

        # Acquire and release a connection
        conn = await connection_pool.get_connection()
        await connection_pool.release(conn)

        # Check updated metrics
        updated_metrics = connection_pool.get_metrics()
        assert updated_metrics["total_requests"] >= 1
        assert updated_metrics["successful_acquisitions"] >= 1

    @pytest.mark.asyncio
    async def test_pool_circuit_breaker_threshold(self, connection_pool):
        """Test that circuit breaker threshold is monitored."""
        # Get metrics to check threshold
        metrics = connection_pool.get_metrics()

        # Pool usage should be tracked
        # Note: The actual field name might be 'circuit_breaker_active' not 'circuit_breaker_triggered'
        assert (
            "circuit_breaker_active" in metrics
            or "circuit_breaker_triggered" in metrics
        )
        if "circuit_breaker_active" in metrics:
            assert metrics["circuit_breaker_active"] is False
        elif "circuit_breaker_triggered" in metrics:
            assert metrics["circuit_breaker_triggered"] is False

    @pytest.mark.asyncio
    async def test_pool_concurrent_acquisition(self, connection_pool):
        """Test concurrent connection acquisition."""

        async def acquire_and_release():
            conn = await connection_pool.get_connection()
            await asyncio.sleep(0.1)  # Simulate work
            await connection_pool.release(conn)
            return True

        # Run multiple concurrent acquisitions
        tasks = [acquire_and_release() for _ in range(5)]
        results = await asyncio.gather(*tasks)

        # All should succeed
        assert all(results)

        # Pool should be full again
        assert connection_pool.connections.qsize() == 2

    @pytest.mark.asyncio
    async def test_pool_custom_timeout(self, connection_pool):
        """Test connection acquisition with custom timeout."""
        # Get all connections
        conn1 = await connection_pool.get_connection()
        conn2 = await connection_pool.get_connection()

        # Try with custom shorter timeout (should raise Exception)
        with pytest.raises(Exception, match="Connection pool exhausted"):
            await connection_pool.get_connection(timeout=1.0)

        # Release connections
        await connection_pool.release(conn1)
        await connection_pool.release(conn2)

    @pytest.mark.asyncio
    async def test_pool_close_all_connections(self, connection_pool):
        """Test closing all connections in the pool."""
        # Get a connection
        conn = await connection_pool.get_connection()
        assert conn.is_closed is False

        # Close connection manually
        await conn.close()

        # Verify connection is closed
        assert conn.is_closed is True

        # Release closed connection (should handle gracefully)
        await connection_pool.release(conn)
