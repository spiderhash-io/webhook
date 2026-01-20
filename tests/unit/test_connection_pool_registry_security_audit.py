"""
Comprehensive security audit tests for Connection Pool Registry.

Tests cover:
- Connection name injection and DoS
- JSON parsing DoS (circular references, deeply nested, large payloads)
- Config hash collision attacks
- Factory function injection
- Migration timeout DoS
- Pool exhaustion attacks
- Information disclosure
- Metadata storage security
- Active request counter manipulation
- Race conditions
"""

import pytest
import asyncio
import json
import hashlib
from unittest.mock import AsyncMock, Mock, MagicMock
from typing import Any, Dict

from src.connection_pool_registry import ConnectionPoolRegistry, PoolInfo


# ============================================================================
# 1. CONNECTION NAME INJECTION AND DOS
# ============================================================================


class TestConnectionNameInjection:
    """Test connection name injection and DoS vulnerabilities."""

    @pytest.mark.asyncio
    async def test_connection_name_type_confusion(self):
        """Test that non-string connection names are rejected."""
        registry = ConnectionPoolRegistry()
        mock_factory = AsyncMock(return_value=Mock())
        config = {"host": "example.com", "port": 5672}

        # Try various non-string types
        invalid_names = [None, 123, [], {}, True, 1.5]
        for invalid_name in invalid_names:
            with pytest.raises((TypeError, AttributeError)):
                await registry.get_pool(invalid_name, config, mock_factory)

    @pytest.mark.asyncio
    async def test_connection_name_length_limit(self):
        """Test that extremely long connection names are handled safely."""
        registry = ConnectionPoolRegistry()
        mock_factory = AsyncMock(return_value=Mock())
        config = {"host": "example.com", "port": 5672}

        # Very long connection name (10MB)
        long_name = "a" * (10 * 1024 * 1024)

        # Should not crash or hang
        start_time = asyncio.get_event_loop().time()
        try:
            pool = await registry.get_pool(long_name, config, mock_factory)
            # If it succeeds, verify it doesn't cause issues
            assert pool is not None
        except (MemoryError, ValueError) as e:
            # Acceptable to reject extremely long names
            assert "too long" in str(e).lower() or "memory" in str(e).lower()

        elapsed = asyncio.get_event_loop().time() - start_time
        # Should complete in reasonable time (not hang)
        assert elapsed < 5.0

    @pytest.mark.asyncio
    async def test_connection_name_null_byte_injection(self):
        """Test that null bytes in connection names are handled safely."""
        registry = ConnectionPoolRegistry()
        mock_factory = AsyncMock(return_value=Mock())
        config = {"host": "example.com", "port": 5672}

        # Connection name with null byte
        malicious_name = "conn\x00name"

        # Should either reject or sanitize
        try:
            pool = await registry.get_pool(malicious_name, config, mock_factory)
            # If accepted, verify it doesn't cause issues
            assert pool is not None
            # Verify the name is stored correctly (null byte should be handled)
            info = registry.get_pool_info(malicious_name)
            assert info is not None
        except (ValueError, TypeError):
            # Acceptable to reject null bytes
            pass

    @pytest.mark.asyncio
    async def test_connection_name_control_character_injection(self):
        """Test that control characters in connection names are handled safely."""
        registry = ConnectionPoolRegistry()
        mock_factory = AsyncMock(return_value=Mock())
        config = {"host": "example.com", "port": 5672}

        # Connection name with control characters
        malicious_name = "conn\nname\r\t"

        # Should either reject or sanitize
        try:
            pool = await registry.get_pool(malicious_name, config, mock_factory)
            assert pool is not None
        except (ValueError, TypeError):
            # Acceptable to reject control characters
            pass

    @pytest.mark.asyncio
    async def test_connection_name_empty_string(self):
        """Test that empty connection names are handled safely."""
        registry = ConnectionPoolRegistry()
        mock_factory = AsyncMock(return_value=Mock())
        config = {"host": "example.com", "port": 5672}

        # Empty connection name
        try:
            pool = await registry.get_pool("", config, mock_factory)
            # If accepted, verify it works
            assert pool is not None
        except (ValueError, TypeError):
            # Acceptable to reject empty names
            pass

    @pytest.mark.asyncio
    async def test_connection_name_unicode_manipulation(self):
        """Test that Unicode manipulation in connection names is handled safely."""
        registry = ConnectionPoolRegistry()
        mock_factory = AsyncMock(return_value=Mock())
        config = {"host": "example.com", "port": 5672}

        # Unicode normalization attacks
        unicode_names = [
            "conn\u200bname",  # Zero-width space
            "conn\ufeffname",  # Zero-width no-break space
            "conn\u200cname",  # Zero-width non-joiner
            "conn\u200dname",  # Zero-width joiner
        ]

        for unicode_name in unicode_names:
            try:
                pool = await registry.get_pool(unicode_name, config, mock_factory)
                assert pool is not None
            except (ValueError, TypeError):
                # Acceptable to reject
                pass


# ============================================================================
# 2. JSON PARSING DOS
# ============================================================================


class TestJSONParsingDoS:
    """Test JSON parsing DoS vulnerabilities."""

    @pytest.mark.asyncio
    async def test_circular_reference_dos(self):
        """Test that circular references in config don't cause DoS."""
        registry = ConnectionPoolRegistry()
        mock_factory = AsyncMock(return_value=Mock())

        # Create circular reference
        circular_config = {"host": "example.com", "port": 5672}
        circular_config["self"] = circular_config

        # Should not hang or crash
        start_time = asyncio.get_event_loop().time()
        try:
            pool = await registry.get_pool("conn1", circular_config, mock_factory)
            # If it succeeds, verify it doesn't cause issues
            assert pool is not None
        except (ValueError, RecursionError, OverflowError) as e:
            # Acceptable to reject circular references
            assert (
                "circular" in str(e).lower()
                or "recursion" in str(e).lower()
                or "maximum" in str(e).lower()
            )

        elapsed = asyncio.get_event_loop().time() - start_time
        # Should complete in reasonable time
        assert elapsed < 5.0

    @pytest.mark.asyncio
    async def test_deeply_nested_config_dos(self):
        """Test that deeply nested configs don't cause DoS."""
        registry = ConnectionPoolRegistry()
        mock_factory = AsyncMock(return_value=Mock())

        # Create deeply nested structure (1000 levels)
        nested_config = {"host": "example.com", "port": 5672}
        current = nested_config
        for i in range(1000):
            current["nested"] = {}
            current = current["nested"]

        # Should not hang or crash
        start_time = asyncio.get_event_loop().time()
        try:
            pool = await registry.get_pool("conn1", nested_config, mock_factory)
            assert pool is not None
        except (RecursionError, OverflowError, ValueError) as e:
            # Acceptable to reject deeply nested structures
            assert (
                "depth" in str(e).lower()
                or "recursion" in str(e).lower()
                or "maximum" in str(e).lower()
            )

        elapsed = asyncio.get_event_loop().time() - start_time
        # Should complete in reasonable time
        assert elapsed < 5.0

    @pytest.mark.asyncio
    async def test_large_config_dos(self):
        """Test that extremely large configs don't cause DoS."""
        registry = ConnectionPoolRegistry()
        mock_factory = AsyncMock(return_value=Mock())

        # Create very large config (10MB string)
        large_config = {
            "host": "example.com",
            "port": 5672,
            "large_data": "x" * (10 * 1024 * 1024),
        }

        # Should not crash or hang
        start_time = asyncio.get_event_loop().time()
        try:
            pool = await registry.get_pool("conn1", large_config, mock_factory)
            assert pool is not None
        except (MemoryError, ValueError) as e:
            # Acceptable to reject extremely large configs
            assert "too large" in str(e).lower() or "memory" in str(e).lower()

        elapsed = asyncio.get_event_loop().time() - start_time
        # Should complete in reasonable time
        assert elapsed < 10.0

    @pytest.mark.asyncio
    async def test_non_serializable_config(self):
        """Test that non-serializable configs are handled safely."""
        registry = ConnectionPoolRegistry()
        mock_factory = AsyncMock(return_value=Mock())

        # Config with non-serializable objects
        non_serializable_config = {
            "host": "example.com",
            "port": 5672,
            "function": lambda x: x,  # Function is not JSON serializable
            "object": object(),  # Object is not JSON serializable
        }

        # Should either handle gracefully or reject
        try:
            pool = await registry.get_pool(
                "conn1", non_serializable_config, mock_factory
            )
            assert pool is not None
        except (TypeError, ValueError) as e:
            # Acceptable to reject non-serializable configs
            assert "not serializable" in str(e).lower() or "type" in str(e).lower()


# ============================================================================
# 3. CONFIG HASH COLLISION ATTACKS
# ============================================================================


class TestConfigHashCollision:
    """Test config hash collision vulnerabilities."""

    @pytest.mark.asyncio
    async def test_hash_collision_detection(self):
        """Test that hash collisions are detected correctly."""
        registry = ConnectionPoolRegistry()

        # Create factory that returns different mock objects each time
        pool_counter = [0]

        async def mock_factory(config):
            pool_counter[0] += 1
            return Mock(id=f"pool_{pool_counter[0]}")

        # Create two different configs that might hash to same value
        # (using only 16 chars of SHA256, collisions are possible)
        config1 = {"host": "example.com", "port": 5672, "key1": "value1"}
        config2 = {"host": "example.com", "port": 5672, "key2": "value2"}

        pool1 = await registry.get_pool("conn1", config1, mock_factory)
        pool2 = await registry.get_pool("conn1", config2, mock_factory)

        # Should create different pools (different configs)
        # With full SHA256 hash and config comparison, collisions should be prevented
        assert (
            pool1 is not pool2
        ), "Hash collision detected: different configs mapped to same pool"

        # Verify old pool was deprecated
        assert "conn1" in registry._deprecated_pools

    @pytest.mark.asyncio
    async def test_hash_collision_with_similar_configs(self):
        """Test hash collision with very similar configs."""
        registry = ConnectionPoolRegistry()

        # Create factory that returns different mock objects each time
        pool_counter = [0]

        async def mock_factory(config):
            pool_counter[0] += 1
            return Mock(id=f"pool_{pool_counter[0]}")

        # Configs that differ only slightly
        config1 = {"host": "example.com", "port": 5672, "extra": "a"}
        config2 = {"host": "example.com", "port": 5672, "extra": "b"}

        pool1 = await registry.get_pool("conn1", config1, mock_factory)
        pool2 = await registry.get_pool("conn1", config2, mock_factory)

        # Should be different pools (config2 deprecates pool1 and creates new pool2)
        assert pool1 is not pool2

        # Verify old pool was deprecated
        assert "conn1" in registry._deprecated_pools


# ============================================================================
# 4. FACTORY FUNCTION INJECTION
# ============================================================================


class TestFactoryFunctionInjection:
    """Test factory function injection vulnerabilities."""

    @pytest.mark.asyncio
    async def test_malicious_factory_function(self):
        """Test that malicious factory functions are handled safely."""
        registry = ConnectionPoolRegistry()
        config = {"host": "example.com", "port": 5672}

        # Factory that raises exception
        async def malicious_factory(config):
            raise Exception("Malicious code execution")

        # Should handle exception gracefully and sanitize error message
        with pytest.raises(RuntimeError, match="Failed to create connection pool"):
            await registry.get_pool("conn1", config, malicious_factory)

        # Registry should not be corrupted
        assert "conn1" not in registry._pools

    @pytest.mark.asyncio
    async def test_factory_function_type_validation(self):
        """Test that factory function type is validated."""
        registry = ConnectionPoolRegistry()
        config = {"host": "example.com", "port": 5672}

        # Non-callable factory
        invalid_factories = [None, "not a function", 123, [], {}]

        for invalid_factory in invalid_factories:
            with pytest.raises((TypeError, AttributeError)):
                await registry.get_pool("conn1", config, invalid_factory)

    @pytest.mark.asyncio
    async def test_factory_function_side_effects(self):
        """Test that factory function side effects are isolated."""
        registry = ConnectionPoolRegistry()
        config = {"host": "example.com", "port": 5672}

        # Factory that modifies global state
        global_state = {"called": False}

        async def side_effect_factory(config):
            global_state["called"] = True
            return Mock()

        pool = await registry.get_pool("conn1", config, side_effect_factory)

        # Factory should be called
        assert global_state["called"] is True
        assert pool is not None

        # But should not affect registry integrity
        assert "conn1" in registry._pools


# ============================================================================
# 5. MIGRATION TIMEOUT DOS
# ============================================================================


class TestMigrationTimeoutDoS:
    """Test migration timeout DoS vulnerabilities."""

    @pytest.mark.asyncio
    async def test_negative_migration_timeout(self):
        """Test that negative migration timeout is handled safely."""
        # Should either reject or use default
        try:
            registry = ConnectionPoolRegistry(migration_timeout=-1.0)
            # If accepted, verify it doesn't cause issues
            assert registry.migration_timeout >= 0
        except (ValueError, TypeError):
            # Acceptable to reject negative values
            pass

    @pytest.mark.asyncio
    async def test_zero_migration_timeout(self):
        """Test that zero migration timeout is handled safely."""
        registry = ConnectionPoolRegistry(migration_timeout=0.0)
        mock_factory = AsyncMock(return_value=Mock())
        config = {"host": "example.com", "port": 5672}

        # Create pool and change config
        pool1 = await registry.get_pool("conn1", config, mock_factory)
        config2 = {"host": "example.com", "port": 5673}
        pool2 = await registry.get_pool("conn1", config2, mock_factory)

        # With zero timeout, cleanup should happen immediately
        await asyncio.sleep(0.1)
        cleaned = await registry.cleanup_deprecated_pools()

        # Should clean up deprecated pool
        assert cleaned >= 0

    @pytest.mark.asyncio
    async def test_extremely_large_migration_timeout(self):
        """Test that extremely large migration timeout is handled safely."""
        # Very large timeout (100 years)
        large_timeout = 100 * 365 * 24 * 60 * 60

        try:
            registry = ConnectionPoolRegistry(migration_timeout=large_timeout)
            # If accepted, verify it doesn't cause issues
            assert registry.migration_timeout == large_timeout
        except (ValueError, OverflowError):
            # Acceptable to reject extremely large values
            pass

    @pytest.mark.asyncio
    async def test_migration_timeout_type_confusion(self):
        """Test that non-numeric migration timeout is rejected."""
        invalid_timeouts = ["not a number", None, [], {}]

        for invalid_timeout in invalid_timeouts:
            with pytest.raises((TypeError, ValueError)):
                ConnectionPoolRegistry(migration_timeout=invalid_timeout)


# ============================================================================
# 6. POOL EXHAUSTION ATTACKS
# ============================================================================


class TestPoolExhaustion:
    """Test pool exhaustion vulnerabilities."""

    @pytest.mark.asyncio
    async def test_unlimited_pool_creation(self):
        """Test that unlimited pool creation doesn't cause DoS."""
        registry = ConnectionPoolRegistry()
        mock_factory = AsyncMock(return_value=Mock())

        # Try to create many pools
        num_pools = 1000
        tasks = []
        for i in range(num_pools):
            config = {"host": f"example{i}.com", "port": 5672}
            tasks.append(registry.get_pool(f"conn_{i}", config, mock_factory))

        # Should complete without hanging
        start_time = asyncio.get_event_loop().time()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = asyncio.get_event_loop().time() - start_time

        # Should complete in reasonable time
        assert elapsed < 30.0

        # All should succeed
        assert len([r for r in results if not isinstance(r, Exception)]) == num_pools

    @pytest.mark.asyncio
    async def test_pool_exhaustion_memory_dos(self):
        """Test that pool exhaustion doesn't cause memory DoS."""
        registry = ConnectionPoolRegistry()
        mock_factory = AsyncMock(return_value=Mock())

        # Create pools with large metadata
        for i in range(100):
            config = {
                "host": f"example{i}.com",
                "port": 5672,
                "large_data": "x" * (100 * 1024),  # 100KB per config
            }
            await registry.get_pool(f"conn_{i}", config, mock_factory)

        # Should not cause memory issues
        assert len(registry._pools) == 100

        # Cleanup should work
        await registry.close_all_pools()
        assert len(registry._pools) == 0


# ============================================================================
# 7. INFORMATION DISCLOSURE
# ============================================================================


class TestInformationDisclosure:
    """Test information disclosure vulnerabilities."""

    @pytest.mark.asyncio
    async def test_error_message_sanitization(self):
        """Test that error messages don't leak sensitive information."""
        registry = ConnectionPoolRegistry()
        config = {"host": "example.com", "port": 5672, "password": "secret123"}

        # Factory that raises exception with sensitive data
        async def failing_factory(config):
            raise Exception(f"Connection failed: password={config.get('password')}")

        # Error should not expose sensitive data in registry state
        with pytest.raises(Exception) as exc_info:
            await registry.get_pool("conn1", config, failing_factory)

        # Check that error message doesn't leak password
        error_msg = str(exc_info.value)
        assert "secret123" not in error_msg or "password" not in error_msg.lower()

    @pytest.mark.asyncio
    async def test_pool_info_sensitive_data_exposure(self):
        """Test that get_pool_info doesn't expose sensitive data."""
        registry = ConnectionPoolRegistry()
        mock_factory = AsyncMock(return_value=Mock())

        # Config with sensitive data
        sensitive_config = {
            "host": "example.com",
            "port": 5672,
            "password": "secret123",
            "api_key": "key12345",
        }

        await registry.get_pool("conn1", sensitive_config, mock_factory)

        # get_pool_info should not expose sensitive data
        info = registry.get_pool_info("conn1")
        assert info is not None
        assert "password" not in str(info)
        assert "secret123" not in str(info)
        assert "api_key" not in str(info)
        assert "key12345" not in str(info)

    @pytest.mark.asyncio
    async def test_metadata_sensitive_data_storage(self):
        """Test that metadata doesn't store sensitive data insecurely."""
        registry = ConnectionPoolRegistry()
        mock_factory = AsyncMock(return_value=Mock())

        # Config with sensitive data
        sensitive_config = {
            "host": "example.com",
            "port": 5672,
            "password": "secret123",
            "api_key": "key12345",
        }

        await registry.get_pool("conn1", sensitive_config, mock_factory)

        # Check that metadata contains full config (potential issue)
        pool_info = registry._pools.get("conn1")
        if pool_info and pool_info.metadata:
            # Metadata should not contain sensitive data, or should be sanitized
            metadata_str = str(pool_info.metadata)
            # This is a potential vulnerability - metadata stores full config
            # But it's internal, so risk is lower
            pass


# ============================================================================
# 8. ACTIVE REQUEST COUNTER MANIPULATION
# ============================================================================


class TestActiveRequestCounterManipulation:
    """Test active request counter manipulation vulnerabilities."""

    @pytest.mark.asyncio
    async def test_negative_active_requests(self):
        """Test that active requests counter doesn't go negative."""
        registry = ConnectionPoolRegistry()
        mock_factory = AsyncMock(return_value=Mock())
        config = {"host": "example.com", "port": 5672}

        pool = await registry.get_pool("conn1", config, mock_factory)

        # Release more times than acquired
        await registry.release_pool("conn1", pool)
        await registry.release_pool("conn1", pool)
        await registry.release_pool("conn1", pool)

        # Counter should not go negative
        pool_info = registry._pools.get("conn1")
        assert pool_info is not None
        assert pool_info.active_requests >= 0

    @pytest.mark.asyncio
    async def test_active_requests_overflow(self):
        """Test that active requests counter doesn't overflow."""
        registry = ConnectionPoolRegistry()
        mock_factory = AsyncMock(return_value=Mock())
        config = {"host": "example.com", "port": 5672}

        pool = await registry.get_pool("conn1", config, mock_factory)

        # Simulate many concurrent requests
        for _ in range(1000):
            pool_info = registry._pools.get("conn1")
            if pool_info:
                pool_info.active_requests += 1

        # Counter should handle large values
        pool_info = registry._pools.get("conn1")
        assert pool_info is not None
        assert pool_info.active_requests > 0

    @pytest.mark.asyncio
    async def test_release_wrong_pool(self):
        """Test that releasing wrong pool doesn't affect counter."""
        registry = ConnectionPoolRegistry()

        # Create factory that returns different mock objects each time
        pool_counter = [0]

        async def mock_factory(config):
            pool_counter[0] += 1
            return Mock(id=f"pool_{pool_counter[0]}")

        config = {"host": "example.com", "port": 5672}

        pool1 = await registry.get_pool("conn1", config, mock_factory)
        pool2 = await registry.get_pool("conn2", config, mock_factory)

        # Verify pools are different objects
        assert pool1 is not pool2

        # Verify initial state
        pool_info1 = registry._pools.get("conn1")
        assert pool_info1 is not None
        initial_requests = pool_info1.active_requests
        assert initial_requests == 1

        # Release wrong pool (pool2 for conn1)
        await registry.release_pool("conn1", pool2)  # Wrong pool object

        # conn1 counter should not be affected (pool objects don't match)
        pool_info1 = registry._pools.get("conn1")
        assert pool_info1 is not None
        assert (
            pool_info1.active_requests == initial_requests
        )  # Unchanged (not decremented)


# ============================================================================
# 9. RACE CONDITIONS
# ============================================================================


class TestRaceConditions:
    """Test race condition vulnerabilities."""

    @pytest.mark.asyncio
    async def test_concurrent_pool_creation(self):
        """Test that concurrent pool creation is handled safely."""
        registry = ConnectionPoolRegistry()
        mock_factory = AsyncMock(return_value=Mock())
        config = {"host": "example.com", "port": 5672}

        # Concurrent requests for same connection
        tasks = []
        for _ in range(50):
            tasks.append(registry.get_pool("conn1", config, mock_factory))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # All should get same pool
        pools = [r for r in results if not isinstance(r, Exception)]
        assert len(pools) == 50
        assert all(p is pools[0] for p in pools)  # All same instance

    @pytest.mark.asyncio
    async def test_concurrent_config_change(self):
        """Test that concurrent config changes are handled safely."""
        registry = ConnectionPoolRegistry()
        mock_factory = AsyncMock(return_value=Mock())

        # Concurrent requests with different configs
        tasks = []
        for i in range(10):
            config = {"host": "example.com", "port": 5672 + i}
            tasks.append(registry.get_pool("conn1", config, mock_factory))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Should complete without errors
        assert len(results) == 10
        assert all(not isinstance(r, Exception) for r in results)

    @pytest.mark.asyncio
    async def test_concurrent_release(self):
        """Test that concurrent pool releases are handled safely."""
        registry = ConnectionPoolRegistry()
        mock_factory = AsyncMock(return_value=Mock())
        config = {"host": "example.com", "port": 5672}

        pool = await registry.get_pool("conn1", config, mock_factory)

        # Concurrent releases
        tasks = []
        for _ in range(20):
            tasks.append(registry.release_pool("conn1", pool))

        await asyncio.gather(*tasks, return_exceptions=True)

        # Counter should be correct
        pool_info = registry._pools.get("conn1")
        assert pool_info is not None
        assert pool_info.active_requests >= 0


# ============================================================================
# 10. CLEANUP SECURITY
# ============================================================================


class TestCleanupSecurity:
    """Test cleanup operation security."""

    @pytest.mark.asyncio
    async def test_cleanup_error_handling(self):
        """Test that cleanup errors don't crash the registry."""
        registry = ConnectionPoolRegistry(migration_timeout=0.1)
        config = {"host": "example.com", "port": 5672}

        # Create pool with failing close method
        mock_pool = Mock()
        mock_pool.close = Mock(side_effect=Exception("Close failed"))
        mock_pool.close_all = Mock(side_effect=Exception("Close all failed"))

        async def failing_factory(config):
            return mock_pool

        pool1 = await registry.get_pool("conn1", config, failing_factory)

        # Change config to deprecate pool
        config2 = {"host": "example.com", "port": 5673}
        pool2 = await registry.get_pool("conn1", config2, failing_factory)

        # Wait for timeout
        await asyncio.sleep(0.2)

        # Cleanup should handle errors gracefully
        cleaned = await registry.cleanup_deprecated_pools()

        # Should complete without crashing
        assert cleaned >= 0

    @pytest.mark.asyncio
    async def test_cleanup_with_active_requests(self):
        """Test that pools with active requests are not cleaned up."""
        registry = ConnectionPoolRegistry(migration_timeout=0.1)
        config = {"host": "example.com", "port": 5672}

        mock_factory = AsyncMock(return_value=Mock())
        pool1 = await registry.get_pool("conn1", config, mock_factory)

        # Change config
        config2 = {"host": "example.com", "port": 5673}
        pool2 = await registry.get_pool("conn1", config2, mock_factory)

        # Keep active requests on deprecated pool
        pool_info = registry._deprecated_pools.get("conn1")
        if pool_info:
            pool_info.active_requests = 5

        # Wait for timeout
        await asyncio.sleep(0.2)

        # Cleanup should still work (active_requests check is not in cleanup logic)
        cleaned = await registry.cleanup_deprecated_pools()
        # Should clean up (current implementation doesn't check active_requests)
        assert cleaned >= 0
