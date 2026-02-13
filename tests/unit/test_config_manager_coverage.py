"""
Coverage tests for src/config_manager.py.

Targets the ~98 missed lines covering:
- ConfigManager.create factory with etcd and unknown backends
- initialize with provider validation failures
- initialize legacy path fallback
- reload_webhooks with file provider, non-file provider, lock contention
- reload_connections with file provider, error paths, pool updates
- reload_all with partial failures
- _validate_webhook_config chain validation, module validation errors
- _validate_connection_config various connection types
- _update_connection_pool for rabbitmq, redis, postgresql, mysql, unknown types
- get_webhook_config / get_all_webhook_configs provider delegation
- get_connection_config / get_all_connection_configs provider delegation
- get_status with provider
"""

import pytest
import json
import os
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock, PropertyMock
from src.config_manager import ConfigManager, ReloadResult


class TestConfigManagerCreate:
    """Test ConfigManager.create factory method."""

    @pytest.mark.asyncio
    async def test_create_file_backend(self):
        """Test creating ConfigManager with file backend."""
        manager = await ConfigManager.create(
            backend="file",
            webhook_config_file="webhooks.json",
            connection_config_file="connections.json",
        )
        assert manager is not None
        assert manager.provider is not None

    @pytest.mark.asyncio
    async def test_create_etcd_backend(self):
        """Test creating ConfigManager with etcd backend."""
        with patch("src.etcd_config_provider.EtcdConfigProvider") as mock_provider:
            mock_provider.return_value = MagicMock()
            manager = await ConfigManager.create(
                backend="etcd",
                host="etcd.example.com",
                port=2379,
                prefix="/cwm/",
                namespace="default",
            )
            assert manager is not None
            mock_provider.assert_called_once_with(
                host="etcd.example.com",
                port=2379,
                prefix="/cwm/",
                namespace="default",
            )

    @pytest.mark.asyncio
    async def test_create_unknown_backend(self):
        """Test creating ConfigManager with unknown backend raises ValueError."""
        with pytest.raises(ValueError, match="Unknown config backend"):
            await ConfigManager.create(backend="memcached")


class TestConfigManagerInitialize:
    """Test ConfigManager.initialize method."""

    @pytest.mark.asyncio
    async def test_initialize_provider_webhook_validation_failure(self):
        """Test initialization fails when provider webhook config validation fails."""
        mock_provider = MagicMock()
        mock_provider.initialize = AsyncMock()
        mock_provider.get_all_webhook_configs.return_value = {
            "bad_webhook": {"data_type": "json"}
            # Missing 'module' field
        }
        mock_provider.get_all_connection_configs.return_value = {}

        manager = ConfigManager(provider=mock_provider)
        result = await manager.initialize()

        assert result.success is False
        assert "Validation failed" in result.error

    @pytest.mark.asyncio
    async def test_initialize_provider_connection_validation_failure(self):
        """Test initialization fails when provider connection config validation fails."""
        mock_provider = MagicMock()
        mock_provider.initialize = AsyncMock()
        mock_provider.get_all_webhook_configs.return_value = {
            "test_wh": {"data_type": "json", "module": "log"}
        }
        mock_provider.get_all_connection_configs.return_value = {
            "bad_conn": {}  # Missing 'type' field
        }

        manager = ConfigManager(provider=mock_provider)
        result = await manager.initialize()

        assert result.success is False
        assert "Validation failed" in result.error

    @pytest.mark.asyncio
    async def test_initialize_provider_success(self):
        """Test successful initialization with provider."""
        mock_provider = MagicMock()
        mock_provider.initialize = AsyncMock()
        mock_provider.get_all_webhook_configs.return_value = {
            "test_wh": {"data_type": "json", "module": "log"}
        }
        mock_provider.get_all_connection_configs.return_value = {}
        mock_provider.get_status.return_value = {"backend": "etcd"}

        manager = ConfigManager(provider=mock_provider)
        result = await manager.initialize()

        assert result.success is True
        assert result.details["webhooks_loaded"] == 1
        assert result.details["backend"] == "etcd"

    @pytest.mark.asyncio
    async def test_initialize_provider_exception(self):
        """Test initialization handles provider exception gracefully."""
        mock_provider = MagicMock()
        mock_provider.initialize = AsyncMock(side_effect=Exception("etcd unavailable"))

        manager = ConfigManager(provider=mock_provider)
        result = await manager.initialize()

        assert result.success is False
        assert "Initialization failed" in result.error

    @pytest.mark.asyncio
    async def test_initialize_legacy_path(self, tmp_path):
        """Test initialization via legacy file loading path (no provider)."""
        webhooks_file = tmp_path / "webhooks.json"
        connections_file = tmp_path / "connections.json"
        webhooks_file.write_text(json.dumps({"wh1": {"data_type": "json", "module": "log"}}))
        connections_file.write_text(
            json.dumps(
                {"conn1": {"type": "rabbitmq", "host": "rmq.example.com", "port": 5672}}
            )
        )

        manager = ConfigManager(
            webhook_config_file=str(webhooks_file),
            connection_config_file=str(connections_file),
        )

        with patch.object(
            manager.pool_registry, "get_pool", new_callable=AsyncMock
        ):
            result = await manager.initialize()

        assert result.success is True
        assert result.details["webhooks_loaded"] == 1

    @pytest.mark.asyncio
    async def test_initialize_legacy_webhook_failure(self, tmp_path):
        """Test initialization fails when legacy webhook reload fails."""
        connections_file = tmp_path / "connections.json"
        connections_file.write_text(json.dumps({}))

        manager = ConfigManager(
            webhook_config_file="/nonexistent/webhooks.json",
            connection_config_file=str(connections_file),
        )

        # Default webhook should be loaded when file not found
        result = await manager.initialize()

        # The _load_webhook_config returns a default webhook when file not found
        # So initialize should succeed with default config
        assert result.success is True


class TestReloadWebhooks:
    """Test ConfigManager.reload_webhooks method."""

    @pytest.mark.asyncio
    async def test_reload_webhooks_file_provider_success(self, tmp_path):
        """Test reloading webhooks with FileConfigProvider."""
        from src.file_config_provider import FileConfigProvider

        webhooks_file = tmp_path / "webhooks.json"
        connections_file = tmp_path / "connections.json"
        webhooks_file.write_text(json.dumps({"wh1": {"data_type": "json", "module": "log"}}))
        connections_file.write_text(json.dumps({}))

        provider = FileConfigProvider(
            webhook_config_file=str(webhooks_file),
            connection_config_file=str(connections_file),
        )

        manager = ConfigManager(provider=provider)
        manager._webhook_config = {}  # Start empty

        result = await manager.reload_webhooks()

        assert result.success is True
        assert result.details["total_webhooks"] == 1

    @pytest.mark.asyncio
    async def test_reload_webhooks_file_provider_validation_error(self, tmp_path):
        """Test reloading webhooks fails with validation error."""
        from src.file_config_provider import FileConfigProvider

        webhooks_file = tmp_path / "webhooks.json"
        connections_file = tmp_path / "connections.json"
        # Invalid: missing module
        webhooks_file.write_text(json.dumps({"bad_wh": {"data_type": "json"}}))
        connections_file.write_text(json.dumps({}))

        provider = FileConfigProvider(
            webhook_config_file=str(webhooks_file),
            connection_config_file=str(connections_file),
        )

        manager = ConfigManager(provider=provider)
        result = await manager.reload_webhooks()

        assert result.success is False
        assert "Validation failed" in result.error
        assert manager._provider_validated is False

    @pytest.mark.asyncio
    async def test_reload_webhooks_file_provider_exception(self, tmp_path):
        """Test reloading webhooks handles provider exception."""
        from src.file_config_provider import FileConfigProvider

        webhooks_file = tmp_path / "webhooks.json"
        connections_file = tmp_path / "connections.json"
        webhooks_file.write_text(json.dumps({"wh1": {"data_type": "json", "module": "log"}}))
        connections_file.write_text(json.dumps({}))

        provider = FileConfigProvider(
            webhook_config_file=str(webhooks_file),
            connection_config_file=str(connections_file),
        )

        manager = ConfigManager(provider=provider)

        # Mock reload_webhooks to raise exception
        with patch.object(provider, "reload_webhooks", side_effect=Exception("Read error")):
            result = await manager.reload_webhooks()

        assert result.success is False
        assert manager._provider_validated is False

    @pytest.mark.asyncio
    async def test_reload_webhooks_non_file_provider(self):
        """Test reloading webhooks with non-file provider returns success with note."""
        mock_provider = MagicMock()
        # Mock it as NOT a FileConfigProvider
        mock_provider.__class__ = type("EtcdConfigProvider", (), {})

        manager = ConfigManager(provider=mock_provider)

        result = await manager.reload_webhooks()

        assert result.success is True
        assert "Provider manages its own updates" in result.details["note"]

    @pytest.mark.asyncio
    async def test_reload_webhooks_legacy_already_in_progress(self, tmp_path):
        """Test reloading webhooks rejects concurrent reloads."""
        manager = ConfigManager()
        manager._reload_in_progress = True

        result = await manager.reload_webhooks()

        assert result.success is False
        assert "already in progress" in result.error

    @pytest.mark.asyncio
    async def test_reload_webhooks_legacy_file_not_found(self):
        """Test reloading webhooks when file doesn't exist (default config)."""
        manager = ConfigManager(webhook_config_file="/nonexistent/webhooks.json")

        result = await manager.reload_webhooks()

        # Default config is returned when file not found
        assert result.success is True

    @pytest.mark.asyncio
    async def test_reload_webhooks_legacy_invalid_json(self, tmp_path):
        """Test reloading webhooks with invalid JSON."""
        webhooks_file = tmp_path / "webhooks.json"
        webhooks_file.write_text("{invalid json")

        manager = ConfigManager(webhook_config_file=str(webhooks_file))

        result = await manager.reload_webhooks()

        assert result.success is False
        assert "Invalid JSON" in result.error

    @pytest.mark.asyncio
    async def test_reload_webhooks_legacy_modified_detection(self, tmp_path):
        """Test reloading webhooks detects modified webhooks."""
        webhooks_file = tmp_path / "webhooks.json"
        webhooks_file.write_text(json.dumps({"wh1": {"data_type": "json", "module": "log"}}))

        manager = ConfigManager(webhook_config_file=str(webhooks_file))
        manager._webhook_config = {
            "wh1": {"data_type": "json", "module": "save_to_disk"}
        }  # Different

        result = await manager.reload_webhooks()

        assert result.success is True
        assert result.details["webhooks_modified"] == 1


class TestReloadConnections:
    """Test ConfigManager.reload_connections method."""

    @pytest.mark.asyncio
    async def test_reload_connections_file_provider_success(self, tmp_path):
        """Test reloading connections with FileConfigProvider."""
        from src.file_config_provider import FileConfigProvider

        webhooks_file = tmp_path / "webhooks.json"
        connections_file = tmp_path / "connections.json"
        webhooks_file.write_text(json.dumps({}))
        connections_file.write_text(
            json.dumps(
                {"conn1": {"type": "rabbitmq", "host": "rmq.example.com", "port": 5672}}
            )
        )

        provider = FileConfigProvider(
            webhook_config_file=str(webhooks_file),
            connection_config_file=str(connections_file),
        )

        manager = ConfigManager(provider=provider)
        manager._connection_config = {}

        result = await manager.reload_connections()

        assert result.success is True
        assert result.details["total_connections"] == 1

    @pytest.mark.asyncio
    async def test_reload_connections_file_provider_validation_error(self, tmp_path):
        """Test reloading connections fails with validation error."""
        from src.file_config_provider import FileConfigProvider

        webhooks_file = tmp_path / "webhooks.json"
        connections_file = tmp_path / "connections.json"
        webhooks_file.write_text(json.dumps({}))
        # Missing type field
        connections_file.write_text(json.dumps({"bad_conn": {"host": "db.example.com"}}))

        provider = FileConfigProvider(
            webhook_config_file=str(webhooks_file),
            connection_config_file=str(connections_file),
        )

        manager = ConfigManager(provider=provider)
        result = await manager.reload_connections()

        assert result.success is False
        assert "Validation failed" in result.error

    @pytest.mark.asyncio
    async def test_reload_connections_non_file_provider(self):
        """Test reloading connections with non-file provider."""
        mock_provider = MagicMock()
        mock_provider.__class__ = type("EtcdConfigProvider", (), {})

        manager = ConfigManager(provider=mock_provider)
        result = await manager.reload_connections()

        assert result.success is True

    @pytest.mark.asyncio
    async def test_reload_connections_legacy_already_in_progress(self):
        """Test reloading connections rejects concurrent reloads."""
        manager = ConfigManager()
        manager._reload_in_progress = True

        result = await manager.reload_connections()

        assert result.success is False
        assert "already in progress" in result.error

    @pytest.mark.asyncio
    async def test_reload_connections_legacy_file_not_found(self):
        """Test reloading connections when file doesn't exist."""
        manager = ConfigManager(connection_config_file="/nonexistent/connections.json")

        result = await manager.reload_connections()

        assert result.success is False
        assert "not found" in result.error

    @pytest.mark.asyncio
    async def test_reload_connections_legacy_invalid_json(self, tmp_path):
        """Test reloading connections with invalid JSON."""
        connections_file = tmp_path / "connections.json"
        connections_file.write_text("{bad json")

        manager = ConfigManager(connection_config_file=str(connections_file))

        result = await manager.reload_connections()

        assert result.success is False
        assert "Invalid JSON" in result.error

    @pytest.mark.asyncio
    async def test_reload_connections_with_pool_updates(self, tmp_path):
        """Test reloading connections triggers pool updates for new connections."""
        connections_file = tmp_path / "connections.json"
        connections_file.write_text(
            json.dumps(
                {"new_conn": {"type": "rabbitmq", "host": "rmq.example.com", "port": 5672}}
            )
        )

        manager = ConfigManager(connection_config_file=str(connections_file))
        manager._connection_config = {}

        with patch.object(
            manager.pool_registry, "get_pool", new_callable=AsyncMock
        ) as mock_pool:
            mock_pool.return_value = MagicMock()
            result = await manager.reload_connections()

        assert result.success is True
        assert result.details["connections_added"] == 1


class TestReloadAll:
    """Test ConfigManager.reload_all method."""

    @pytest.mark.asyncio
    async def test_reload_all_both_success(self, tmp_path):
        """Test reload_all when both succeed."""
        webhooks_file = tmp_path / "webhooks.json"
        connections_file = tmp_path / "connections.json"
        webhooks_file.write_text(json.dumps({"wh1": {"data_type": "json", "module": "log"}}))
        connections_file.write_text(
            json.dumps(
                {"conn1": {"type": "rabbitmq", "host": "rmq.example.com", "port": 5672}}
            )
        )

        manager = ConfigManager(
            webhook_config_file=str(webhooks_file),
            connection_config_file=str(connections_file),
        )

        with patch.object(
            manager.pool_registry, "get_pool", new_callable=AsyncMock
        ):
            result = await manager.reload_all()

        assert result.success is True
        assert "webhooks" in result.details
        assert "connections" in result.details

    @pytest.mark.asyncio
    async def test_reload_all_webhooks_fail(self, tmp_path):
        """Test reload_all when webhooks fail but connections succeed."""
        webhooks_file = tmp_path / "webhooks.json"
        connections_file = tmp_path / "connections.json"
        webhooks_file.write_text("{invalid json")
        connections_file.write_text(
            json.dumps(
                {"conn1": {"type": "rabbitmq", "host": "rmq.example.com", "port": 5672}}
            )
        )

        manager = ConfigManager(
            webhook_config_file=str(webhooks_file),
            connection_config_file=str(connections_file),
        )

        with patch.object(
            manager.pool_registry, "get_pool", new_callable=AsyncMock
        ):
            result = await manager.reload_all()

        assert result.success is False
        assert "Webhooks:" in result.error


class TestValidateWebhookConfig:
    """Test ConfigManager._validate_webhook_config method."""

    @pytest.mark.asyncio
    async def test_validate_webhook_invalid_id(self):
        """Test validation rejects empty webhook ID."""
        manager = ConfigManager()
        result = await manager._validate_webhook_config(
            {"": {"data_type": "json", "module": "log"}}
        )
        assert result is not None
        assert "Invalid webhook ID" in result

    @pytest.mark.asyncio
    async def test_validate_webhook_with_chain(self):
        """Test validation of webhook with chain configuration."""
        manager = ConfigManager()
        result = await manager._validate_webhook_config(
            {
                "chain_wh": {
                    "data_type": "json",
                    "chain": ["log", "save_to_disk"],
                    "chain-config": {"execution": "sequential"},
                }
            }
        )
        # Chain config is valid
        assert result is None

    @pytest.mark.asyncio
    async def test_validate_webhook_with_invalid_chain(self):
        """Test validation rejects invalid chain configuration."""
        manager = ConfigManager()
        result = await manager._validate_webhook_config(
            {
                "chain_wh": {
                    "data_type": "json",
                    "chain": "not_a_list",
                }
            }
        )
        assert result is not None
        assert "invalid chain" in result.lower()

    @pytest.mark.asyncio
    async def test_validate_webhook_missing_module(self):
        """Test validation rejects webhook without module or chain."""
        manager = ConfigManager()
        result = await manager._validate_webhook_config(
            {"wh1": {"data_type": "json"}}
        )
        assert result is not None
        assert "missing required 'module' field" in result

    @pytest.mark.asyncio
    async def test_validate_webhook_unknown_module(self):
        """Test validation rejects unknown module name."""
        manager = ConfigManager()
        result = await manager._validate_webhook_config(
            {"wh1": {"data_type": "json", "module": "nonexistent_module"}}
        )
        assert result is not None
        assert "unknown module" in result


class TestValidateConnectionConfig:
    """Test ConfigManager._validate_connection_config method."""

    @pytest.mark.asyncio
    async def test_validate_connection_invalid_name(self):
        """Test validation rejects empty connection name."""
        manager = ConfigManager()
        result = await manager._validate_connection_config(
            {"": {"type": "rabbitmq", "host": "localhost", "port": 5672}}
        )
        assert result is not None
        assert "Invalid connection name" in result

    @pytest.mark.asyncio
    async def test_validate_connection_missing_type(self):
        """Test validation rejects connection without type."""
        manager = ConfigManager()
        result = await manager._validate_connection_config(
            {"conn1": {"host": "db.example.com", "port": 5432}}
        )
        assert result is not None
        assert "missing required 'type' field" in result

    @pytest.mark.asyncio
    async def test_validate_connection_missing_host(self):
        """Test validation rejects connection without host (for types that need it)."""
        manager = ConfigManager()
        result = await manager._validate_connection_config(
            {"conn1": {"type": "postgresql", "port": 5432}}
        )
        assert result is not None
        assert "missing required 'host' field" in result

    @pytest.mark.asyncio
    async def test_validate_connection_missing_port(self):
        """Test validation rejects connection without port."""
        manager = ConfigManager()
        result = await manager._validate_connection_config(
            {"conn1": {"type": "postgresql", "host": "db.example.com"}}
        )
        assert result is not None
        assert "missing required 'port' field" in result

    @pytest.mark.asyncio
    async def test_validate_connection_host_validation_error(self):
        """Test validation handles host validation failure (SSRF protection)."""
        manager = ConfigManager()

        with patch("src.config_manager._validate_connection_host") as mock_validate:
            mock_validate.side_effect = ValueError("Dangerous host")
            result = await manager._validate_connection_config(
                {
                    "conn1": {
                        "type": "rabbitmq",
                        "host": "169.254.169.254",
                        "port": 5672,
                    }
                }
            )
            assert result is not None
            assert "host validation failed" in result

    @pytest.mark.asyncio
    async def test_validate_connection_port_validation_error(self):
        """Test validation handles port validation failure."""
        manager = ConfigManager()

        with patch(
            "src.config_manager._validate_connection_host", return_value="db.example.com"
        ), patch("src.config_manager._validate_connection_port") as mock_port:
            mock_port.side_effect = ValueError("Port out of range")
            result = await manager._validate_connection_config(
                {"conn1": {"type": "mysql", "host": "db.example.com", "port": 99999}}
            )
            assert result is not None
            assert "port validation failed" in result


class TestUpdateConnectionPool:
    """Test ConfigManager._update_connection_pool method."""

    @pytest.mark.asyncio
    async def test_update_pool_rabbitmq(self):
        """Test pool update for RabbitMQ connection."""
        manager = ConfigManager()
        with patch.object(
            manager.pool_registry, "get_pool", new_callable=AsyncMock
        ) as mock_pool:
            mock_pool.return_value = MagicMock()
            await manager._update_connection_pool(
                "rmq_conn", {"type": "rabbitmq", "host": "rmq.example.com", "port": 5672}
            )
            mock_pool.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_pool_redis(self):
        """Test pool update for Redis connection."""
        manager = ConfigManager()
        with patch.object(
            manager.pool_registry, "get_pool", new_callable=AsyncMock
        ) as mock_pool:
            mock_pool.return_value = MagicMock()
            await manager._update_connection_pool(
                "redis_conn", {"type": "redis-rq", "host": "redis.example.com", "port": 6379}
            )
            mock_pool.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_pool_postgresql(self):
        """Test pool update for PostgreSQL connection."""
        manager = ConfigManager()
        with patch.object(
            manager.pool_registry, "get_pool", new_callable=AsyncMock
        ) as mock_pool:
            mock_pool.return_value = MagicMock()
            await manager._update_connection_pool(
                "pg_conn",
                {"type": "postgresql", "host": "pg.example.com", "port": 5432},
            )
            mock_pool.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_pool_postgres_alias(self):
        """Test pool update for 'postgres' type alias."""
        manager = ConfigManager()
        with patch.object(
            manager.pool_registry, "get_pool", new_callable=AsyncMock
        ) as mock_pool:
            mock_pool.return_value = MagicMock()
            await manager._update_connection_pool(
                "pg_conn", {"type": "postgres", "host": "pg.example.com", "port": 5432}
            )
            mock_pool.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_pool_mysql(self):
        """Test pool update for MySQL connection."""
        manager = ConfigManager()
        with patch.object(
            manager.pool_registry, "get_pool", new_callable=AsyncMock
        ) as mock_pool:
            mock_pool.return_value = MagicMock()
            await manager._update_connection_pool(
                "mysql_conn",
                {"type": "mysql", "host": "mysql.example.com", "port": 3306},
            )
            mock_pool.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_pool_mariadb_alias(self):
        """Test pool update for 'mariadb' type alias."""
        manager = ConfigManager()
        with patch.object(
            manager.pool_registry, "get_pool", new_callable=AsyncMock
        ) as mock_pool:
            mock_pool.return_value = MagicMock()
            await manager._update_connection_pool(
                "maria_conn",
                {"type": "mariadb", "host": "maria.example.com", "port": 3306},
            )
            mock_pool.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_pool_unknown_type(self):
        """Test pool update for unknown type is a no-op."""
        manager = ConfigManager()
        with patch.object(
            manager.pool_registry, "get_pool", new_callable=AsyncMock
        ) as mock_pool:
            await manager._update_connection_pool(
                "unknown_conn", {"type": "kafka", "bootstrap_servers": "kafka:9092"}
            )
            mock_pool.assert_not_called()

    @pytest.mark.asyncio
    async def test_update_pool_creation_failure(self):
        """Test pool update handles pool creation failure gracefully."""
        manager = ConfigManager()
        with patch.object(
            manager.pool_registry, "get_pool", new_callable=AsyncMock
        ) as mock_pool:
            mock_pool.side_effect = Exception("Connection refused")
            # Should not raise - just log warning
            await manager._update_connection_pool(
                "rmq_conn",
                {"type": "rabbitmq", "host": "rmq.example.com", "port": 5672},
            )


class TestConfigManagerProviderDelegation:
    """Test ConfigManager provider delegation for config access."""

    def test_get_webhook_config_with_provider(self):
        """Test get_webhook_config delegates to provider when validated."""
        mock_provider = MagicMock()
        mock_provider.get_webhook_config.return_value = {"data_type": "json", "module": "log"}

        manager = ConfigManager(provider=mock_provider)
        manager._provider_validated = True

        config = manager.get_webhook_config("test_wh")
        assert config is not None
        mock_provider.get_webhook_config.assert_called_once_with(
            "test_wh", namespace=None
        )

    def test_get_webhook_config_without_provider_validation(self):
        """Test get_webhook_config falls back to cache when provider not validated."""
        mock_provider = MagicMock()

        manager = ConfigManager(provider=mock_provider)
        manager._provider_validated = False
        manager._webhook_config = {"test_wh": {"module": "log"}}

        config = manager.get_webhook_config("test_wh")
        assert config == {"module": "log"}
        mock_provider.get_webhook_config.assert_not_called()

    def test_get_all_webhook_configs_with_provider(self):
        """Test get_all_webhook_configs delegates to provider."""
        mock_provider = MagicMock()
        mock_provider.get_all_webhook_configs.return_value = {"wh1": {"module": "log"}}

        manager = ConfigManager(provider=mock_provider)
        manager._provider_validated = True

        configs = manager.get_all_webhook_configs(namespace="staging")
        assert "wh1" in configs
        mock_provider.get_all_webhook_configs.assert_called_once_with(
            namespace="staging"
        )

    def test_get_all_webhook_configs_without_provider(self):
        """Test get_all_webhook_configs returns deep copy when no provider."""
        manager = ConfigManager()
        manager._webhook_config = {"wh1": {"module": "log"}}

        configs = manager.get_all_webhook_configs()
        assert "wh1" in configs
        # Verify it's a deep copy
        configs["wh1"]["module"] = "changed"
        assert manager._webhook_config["wh1"]["module"] == "log"

    def test_get_connection_config_with_provider(self):
        """Test get_connection_config delegates to provider."""
        mock_provider = MagicMock()
        mock_provider.get_connection_config.return_value = {"type": "rabbitmq"}

        manager = ConfigManager(provider=mock_provider)
        manager._provider_validated = True

        config = manager.get_connection_config("rmq_conn")
        assert config == {"type": "rabbitmq"}

    def test_get_all_connection_configs_with_provider(self):
        """Test get_all_connection_configs delegates to provider."""
        mock_provider = MagicMock()
        mock_provider.get_all_connection_configs.return_value = {
            "conn1": {"type": "rabbitmq"}
        }

        manager = ConfigManager(provider=mock_provider)
        manager._provider_validated = True

        configs = manager.get_all_connection_configs()
        assert "conn1" in configs

    def test_get_status_with_provider(self):
        """Test get_status includes provider status."""
        mock_provider = MagicMock()
        mock_provider.get_status.return_value = {"backend": "etcd", "connected": True}

        manager = ConfigManager(provider=mock_provider)
        status = manager.get_status()

        assert "provider" in status
        assert status["provider"]["backend"] == "etcd"

    def test_get_status_without_provider(self):
        """Test get_status without provider."""
        manager = ConfigManager()
        status = manager.get_status()

        assert "provider" not in status
        assert "webhooks_count" in status
        assert "connections_count" in status


class TestReloadResult:
    """Test ReloadResult dataclass."""

    def test_reload_result_auto_timestamp(self):
        """Test that ReloadResult auto-generates timestamp."""
        result = ReloadResult(success=True)
        assert result.timestamp != ""
        assert "T" in result.timestamp  # ISO format

    def test_reload_result_with_details(self):
        """Test ReloadResult with all fields."""
        result = ReloadResult(
            success=False,
            error="Test error",
            details={"key": "value"},
        )
        assert result.success is False
        assert result.error == "Test error"
        assert result.details == {"key": "value"}
