"""
Coverage tests for src/main.py.

Targets the ~326 missed lines covering:
- startup_logic: etcd backend, clickhouse initialization, webhook connect, file watcher
- shutdown_logic: all error paths, cleanup task cancellation
- validate_connections: postgresql, mysql, kafka, redis, rabbitmq, clickhouse paths
- Route handlers: webhook processing with retry, namespaced webhooks, stats, admin endpoints
- CORS validation edge cases
- SecurityHeadersMiddleware edge cases
- _require_admin_token edge cases
"""

import pytest
import asyncio
import os
import time
from unittest.mock import Mock, AsyncMock, patch, MagicMock, PropertyMock
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient


# ============================================================================
# startup_logic tests
# ============================================================================


class TestStartupLogicEtcdBackend:
    """Test startup_logic with etcd backend."""

    @pytest.mark.asyncio
    async def test_startup_with_etcd_backend(self):
        """Test startup with CONFIG_BACKEND=etcd."""
        from src.main import startup_logic

        test_app = FastAPI()

        mock_cm = MagicMock()
        mock_cm.initialize = AsyncMock(
            return_value=Mock(
                success=True,
                details={
                    "webhooks_loaded": 2,
                    "connections_loaded": 1,
                    "backend": "etcd",
                },
            )
        )
        mock_cm.get_all_connection_configs.return_value = {}
        mock_cm.provider = None

        with patch("src.main.CONFIG_BACKEND", "etcd"), patch(
            "src.main.ConfigManager"
        ) as mock_cm_class, patch.dict(
            os.environ,
            {
                "ETCD_HOST": "etcd.example.com",
                "ETCD_PORT": "2379",
                "ETCD_PREFIX": "/test/",
                "ETCD_NAMESPACE": "staging",
                "ETCD_USERNAME": "user",
                "ETCD_PASSWORD": "pass",
            },
        ):
            mock_cm_class.create = AsyncMock(return_value=mock_cm)

            await startup_logic(test_app)

            mock_cm_class.create.assert_called_once_with(
                backend="etcd",
                host="etcd.example.com",
                port=2379,
                prefix="/test/",
                namespace="staging",
                username="user",
                password="pass",
            )

    @pytest.mark.asyncio
    async def test_startup_init_result_failure(self):
        """Test startup when ConfigManager.initialize returns failure."""
        from src.main import startup_logic

        test_app = FastAPI()

        mock_cm = MagicMock()
        mock_cm.initialize = AsyncMock(
            return_value=Mock(
                success=False,
                error="Validation failed: missing module",
                details={},
            )
        )
        mock_cm.get_all_connection_configs.return_value = {}
        mock_cm.provider = None

        with patch("src.main.ConfigManager") as mock_cm_class, patch(
            "src.main.connection_config", {}
        ):
            mock_cm_class.create = AsyncMock(return_value=mock_cm)

            # Should not raise - just prints warning
            await startup_logic(test_app)


class TestStartupLogicClickHouse:
    """Test startup_logic ClickHouse initialization paths."""

    @pytest.mark.asyncio
    async def test_startup_clickhouse_init_success(self):
        """Test ClickHouse logger initialization success."""
        from src.main import startup_logic

        test_app = FastAPI()

        mock_cm = MagicMock()
        mock_cm.initialize = AsyncMock(
            return_value=Mock(
                success=True,
                details={"webhooks_loaded": 0, "connections_loaded": 1, "backend": "file"},
            )
        )
        mock_cm.get_all_connection_configs.return_value = {
            "ch_conn": {"type": "clickhouse", "host": "ch.example.com", "port": 9000}
        }
        mock_cm.provider = None

        mock_ch_logger = MagicMock()
        mock_ch_logger.connect = AsyncMock()

        with patch("src.main.ConfigManager") as mock_cm_class, patch(
            "src.main.ClickHouseAnalytics", return_value=mock_ch_logger
        ), patch("src.main.connection_config", {}):
            mock_cm_class.create = AsyncMock(return_value=mock_cm)

            await startup_logic(test_app)

            assert test_app.state.clickhouse_logger == mock_ch_logger
            mock_ch_logger.connect.assert_called_once()

    @pytest.mark.asyncio
    async def test_startup_clickhouse_init_failure(self):
        """Test ClickHouse logger initialization failure (graceful degradation)."""
        from src.main import startup_logic

        test_app = FastAPI()

        mock_cm = MagicMock()
        mock_cm.initialize = AsyncMock(
            return_value=Mock(
                success=True,
                details={"webhooks_loaded": 0, "connections_loaded": 1, "backend": "file"},
            )
        )
        mock_cm.get_all_connection_configs.return_value = {
            "ch_conn": {"type": "clickhouse", "host": "ch.example.com", "port": 9000}
        }
        mock_cm.provider = None

        mock_ch_logger = MagicMock()
        mock_ch_logger.connect = AsyncMock(side_effect=Exception("Connection refused"))

        with patch("src.main.ConfigManager") as mock_cm_class, patch(
            "src.main.ClickHouseAnalytics", return_value=mock_ch_logger
        ), patch("src.main.connection_config", {}):
            mock_cm_class.create = AsyncMock(return_value=mock_cm)

            await startup_logic(test_app)

            # Should set to None on failure
            assert test_app.state.clickhouse_logger is None

    @pytest.mark.asyncio
    async def test_startup_clickhouse_from_legacy_config(self):
        """Test ClickHouse config from legacy connection_config when no ConfigManager."""
        from src.main import startup_logic

        test_app = FastAPI()

        legacy_connections = {
            "ch_conn": {"type": "clickhouse", "host": "ch.example.com", "port": 9000}
        }

        mock_ch_logger = MagicMock()
        mock_ch_logger.connect = AsyncMock()

        with patch("src.main.ConfigManager") as mock_cm_class, patch(
            "src.main.inject_connection_details", AsyncMock(return_value={})
        ), patch("src.main.webhook_config_data", {}), patch(
            "src.main.connection_config", legacy_connections
        ), patch(
            "src.main.ClickHouseAnalytics", return_value=mock_ch_logger
        ):
            mock_cm_class.create = AsyncMock(side_effect=Exception("Init failed"))

            await startup_logic(test_app)

            # Should find clickhouse from legacy config
            assert test_app.state.clickhouse_logger == mock_ch_logger


class TestStartupLogicWebhookConnect:
    """Test startup_logic Webhook Connect initialization."""

    @pytest.mark.asyncio
    async def test_startup_webhook_connect_enabled(self):
        """Test Webhook Connect initialization when enabled."""
        from src.main import startup_logic

        test_app = FastAPI()

        mock_cm = MagicMock()
        mock_cm.initialize = AsyncMock(
            return_value=Mock(
                success=True,
                details={"webhooks_loaded": 0, "connections_loaded": 0, "backend": "file"},
            )
        )
        mock_cm.get_all_connection_configs.return_value = {}
        mock_cm.provider = None

        mock_channel_manager = MagicMock()
        mock_channel_manager.start = AsyncMock()

        with patch("src.main.ConfigManager") as mock_cm_class, patch.dict(
            os.environ, {"WEBHOOK_CONNECT_ENABLED": "true"}
        ), patch("src.main.ChannelManager", return_value=mock_channel_manager), patch(
            "src.main.RabbitMQBuffer"
        ), patch(
            "src.main.WebhookConnectModule"
        ), patch(
            "src.main.webhook_connect_api"
        ), patch(
            "src.main.webhook_connect_admin_api"
        ), patch(
            "src.main.connection_config", {}
        ):
            mock_cm_class.create = AsyncMock(return_value=mock_cm)

            await startup_logic(test_app)

            assert test_app.state.webhook_connect_channel_manager == mock_channel_manager
            mock_channel_manager.start.assert_called_once()

    @pytest.mark.asyncio
    async def test_startup_webhook_connect_failure(self):
        """Test Webhook Connect initialization failure (graceful degradation)."""
        from src.main import startup_logic

        test_app = FastAPI()

        mock_cm = MagicMock()
        mock_cm.initialize = AsyncMock(
            return_value=Mock(
                success=True,
                details={"webhooks_loaded": 0, "connections_loaded": 0, "backend": "file"},
            )
        )
        mock_cm.get_all_connection_configs.return_value = {}
        mock_cm.provider = None

        with patch("src.main.ConfigManager") as mock_cm_class, patch.dict(
            os.environ, {"WEBHOOK_CONNECT_ENABLED": "true"}
        ), patch(
            "src.main.RabbitMQBuffer", side_effect=Exception("RabbitMQ unavailable")
        ), patch(
            "src.main.connection_config", {}
        ):
            mock_cm_class.create = AsyncMock(return_value=mock_cm)

            await startup_logic(test_app)

            assert test_app.state.webhook_connect_channel_manager is None


class TestStartupLogicFileWatcher:
    """Test startup_logic file watcher initialization."""

    @pytest.mark.asyncio
    async def test_startup_file_watcher_enabled(self):
        """Test file watcher start when enabled."""
        from src.main import startup_logic

        test_app = FastAPI()

        mock_cm = MagicMock()
        mock_cm.initialize = AsyncMock(
            return_value=Mock(
                success=True,
                details={"webhooks_loaded": 0, "connections_loaded": 0, "backend": "file"},
            )
        )
        mock_cm.get_all_connection_configs.return_value = {}
        mock_cm.provider = None

        mock_watcher = MagicMock()

        with patch("src.main.ConfigManager") as mock_cm_class, patch(
            "src.main.CONFIG_BACKEND", "file"
        ), patch.dict(
            os.environ,
            {
                "CONFIG_FILE_WATCHING_ENABLED": "true",
                "CONFIG_RELOAD_DEBOUNCE_SECONDS": "5.0",
            },
        ), patch(
            "src.main.ConfigFileWatcher", return_value=mock_watcher
        ), patch(
            "src.main.connection_config", {}
        ):
            mock_cm_class.create = AsyncMock(return_value=mock_cm)

            await startup_logic(test_app)

            assert test_app.state.config_watcher == mock_watcher
            mock_watcher.start.assert_called_once()

    @pytest.mark.asyncio
    async def test_startup_file_watcher_debounce_too_small(self):
        """Test file watcher debounce validation (too small)."""
        from src.main import startup_logic

        test_app = FastAPI()

        mock_cm = MagicMock()
        mock_cm.initialize = AsyncMock(
            return_value=Mock(
                success=True,
                details={"webhooks_loaded": 0, "connections_loaded": 0, "backend": "file"},
            )
        )
        mock_cm.get_all_connection_configs.return_value = {}
        mock_cm.provider = None

        mock_watcher = MagicMock()

        with patch("src.main.ConfigManager") as mock_cm_class, patch(
            "src.main.CONFIG_BACKEND", "file"
        ), patch.dict(
            os.environ,
            {
                "CONFIG_FILE_WATCHING_ENABLED": "true",
                "CONFIG_RELOAD_DEBOUNCE_SECONDS": "0.001",
            },
        ), patch(
            "src.main.ConfigFileWatcher", return_value=mock_watcher
        ) as mock_watcher_cls, patch(
            "src.main.connection_config", {}
        ):
            mock_cm_class.create = AsyncMock(return_value=mock_cm)

            await startup_logic(test_app)

            # Should default to 3.0 if value too small
            mock_watcher_cls.assert_called_once_with(mock_cm, debounce_seconds=3.0)

    @pytest.mark.asyncio
    async def test_startup_file_watcher_debounce_too_large(self):
        """Test file watcher debounce validation (too large, capped at 3600)."""
        from src.main import startup_logic

        test_app = FastAPI()

        mock_cm = MagicMock()
        mock_cm.initialize = AsyncMock(
            return_value=Mock(
                success=True,
                details={"webhooks_loaded": 0, "connections_loaded": 0, "backend": "file"},
            )
        )
        mock_cm.get_all_connection_configs.return_value = {}
        mock_cm.provider = None

        mock_watcher = MagicMock()

        with patch("src.main.ConfigManager") as mock_cm_class, patch(
            "src.main.CONFIG_BACKEND", "file"
        ), patch.dict(
            os.environ,
            {
                "CONFIG_FILE_WATCHING_ENABLED": "true",
                "CONFIG_RELOAD_DEBOUNCE_SECONDS": "99999",
            },
        ), patch(
            "src.main.ConfigFileWatcher", return_value=mock_watcher
        ) as mock_watcher_cls, patch(
            "src.main.connection_config", {}
        ):
            mock_cm_class.create = AsyncMock(return_value=mock_cm)

            await startup_logic(test_app)

            mock_watcher_cls.assert_called_once_with(mock_cm, debounce_seconds=3600)

    @pytest.mark.asyncio
    async def test_startup_file_watcher_debounce_invalid(self):
        """Test file watcher debounce validation (invalid value)."""
        from src.main import startup_logic

        test_app = FastAPI()

        mock_cm = MagicMock()
        mock_cm.initialize = AsyncMock(
            return_value=Mock(
                success=True,
                details={"webhooks_loaded": 0, "connections_loaded": 0, "backend": "file"},
            )
        )
        mock_cm.get_all_connection_configs.return_value = {}
        mock_cm.provider = None

        mock_watcher = MagicMock()

        with patch("src.main.ConfigManager") as mock_cm_class, patch(
            "src.main.CONFIG_BACKEND", "file"
        ), patch.dict(
            os.environ,
            {
                "CONFIG_FILE_WATCHING_ENABLED": "true",
                "CONFIG_RELOAD_DEBOUNCE_SECONDS": "not-a-number",
            },
        ), patch(
            "src.main.ConfigFileWatcher", return_value=mock_watcher
        ) as mock_watcher_cls, patch(
            "src.main.connection_config", {}
        ):
            mock_cm_class.create = AsyncMock(return_value=mock_cm)

            await startup_logic(test_app)

            mock_watcher_cls.assert_called_once_with(mock_cm, debounce_seconds=3.0)


# ============================================================================
# shutdown_logic tests
# ============================================================================


class TestShutdownLogic:
    """Test shutdown_logic paths."""

    @pytest.mark.asyncio
    async def test_shutdown_config_watcher_error(self):
        """Test shutdown handles config watcher stop failure."""
        from src.main import shutdown_logic

        test_app = FastAPI()
        test_app.state.config_watcher = MagicMock()
        test_app.state.config_watcher.stop.side_effect = Exception("Watcher stop error")
        test_app.state.config_manager = None
        test_app.state.clickhouse_logger = None
        test_app.state.webhook_connect_channel_manager = None
        test_app.state.cleanup_task = None

        with patch("src.main.stats") as mock_stats:
            mock_stats.close = AsyncMock()
            # Should not raise
            await shutdown_logic(test_app)

    @pytest.mark.asyncio
    async def test_shutdown_config_manager_pool_close_error(self):
        """Test shutdown handles connection pool close failure."""
        from src.main import shutdown_logic

        test_app = FastAPI()
        test_app.state.config_watcher = None
        test_app.state.config_manager = MagicMock()
        test_app.state.config_manager.pool_registry.close_all_pools = AsyncMock(
            side_effect=Exception("Pool close error")
        )
        test_app.state.config_manager.provider = MagicMock()
        test_app.state.config_manager.provider.shutdown = AsyncMock()
        test_app.state.clickhouse_logger = None
        test_app.state.webhook_connect_channel_manager = None
        test_app.state.cleanup_task = None

        with patch("src.main.stats") as mock_stats:
            mock_stats.close = AsyncMock()
            await shutdown_logic(test_app)

    @pytest.mark.asyncio
    async def test_shutdown_provider_shutdown_error(self):
        """Test shutdown handles provider shutdown failure."""
        from src.main import shutdown_logic

        test_app = FastAPI()
        test_app.state.config_watcher = None
        test_app.state.config_manager = MagicMock()
        test_app.state.config_manager.pool_registry.close_all_pools = AsyncMock()
        test_app.state.config_manager.provider = MagicMock()
        test_app.state.config_manager.provider.shutdown = AsyncMock(
            side_effect=Exception("Provider shutdown error")
        )
        test_app.state.clickhouse_logger = None
        test_app.state.webhook_connect_channel_manager = None
        test_app.state.cleanup_task = None

        with patch("src.main.stats") as mock_stats:
            mock_stats.close = AsyncMock()
            await shutdown_logic(test_app)

    @pytest.mark.asyncio
    async def test_shutdown_clickhouse_disconnect_error(self):
        """Test shutdown handles ClickHouse disconnect failure."""
        from src.main import shutdown_logic

        test_app = FastAPI()
        test_app.state.config_watcher = None
        test_app.state.config_manager = None
        test_app.state.clickhouse_logger = MagicMock()
        test_app.state.clickhouse_logger.disconnect = AsyncMock(
            side_effect=Exception("ClickHouse disconnect error")
        )
        test_app.state.webhook_connect_channel_manager = None
        test_app.state.cleanup_task = None

        with patch("src.main.stats") as mock_stats:
            mock_stats.close = AsyncMock()
            await shutdown_logic(test_app)

    @pytest.mark.asyncio
    async def test_shutdown_webhook_connect_stop_error(self):
        """Test shutdown handles Webhook Connect stop failure."""
        from src.main import shutdown_logic

        test_app = FastAPI()
        test_app.state.config_watcher = None
        test_app.state.config_manager = None
        test_app.state.clickhouse_logger = None
        test_app.state.webhook_connect_channel_manager = MagicMock()
        test_app.state.webhook_connect_channel_manager.stop = AsyncMock(
            side_effect=Exception("WebhookConnect stop error")
        )
        test_app.state.cleanup_task = None

        with patch("src.main.stats") as mock_stats:
            mock_stats.close = AsyncMock()
            await shutdown_logic(test_app)

    @pytest.mark.asyncio
    async def test_shutdown_redis_stats_close_error(self):
        """Test shutdown handles Redis stats close failure."""
        from src.main import shutdown_logic

        test_app = FastAPI()
        test_app.state.config_watcher = None
        test_app.state.config_manager = None
        test_app.state.clickhouse_logger = None
        test_app.state.webhook_connect_channel_manager = None
        test_app.state.cleanup_task = None

        with patch("src.main.stats") as mock_stats:
            mock_stats.close = AsyncMock(side_effect=Exception("Redis close error"))
            await shutdown_logic(test_app)

    @pytest.mark.asyncio
    async def test_shutdown_cleanup_task_cancellation(self):
        """Test shutdown cancels cleanup task properly."""
        from src.main import shutdown_logic

        test_app = FastAPI()
        test_app.state.config_watcher = None
        test_app.state.config_manager = None
        test_app.state.clickhouse_logger = None
        test_app.state.webhook_connect_channel_manager = None

        # Create a mock task that behaves like asyncio.Task
        mock_task = MagicMock()
        mock_task.cancel = MagicMock()
        # Make it awaitable via asyncio.wait_for
        mock_future = asyncio.Future()
        mock_future.set_exception(asyncio.CancelledError())

        test_app.state.cleanup_task = mock_task

        with patch("src.main.stats") as mock_stats, patch(
            "asyncio.wait_for", new_callable=AsyncMock
        ) as mock_wait:
            mock_stats.close = AsyncMock()
            mock_wait.side_effect = asyncio.CancelledError()

            await shutdown_logic(test_app)

            mock_task.cancel.assert_called_once()

    @pytest.mark.asyncio
    async def test_shutdown_cleanup_task_general_error(self):
        """Test shutdown handles general error during cleanup task cancellation."""
        from src.main import shutdown_logic

        test_app = FastAPI()
        test_app.state.config_watcher = None
        test_app.state.config_manager = None
        test_app.state.clickhouse_logger = None
        test_app.state.webhook_connect_channel_manager = None

        mock_task = MagicMock()
        mock_task.cancel.side_effect = Exception("Unexpected cancel error")
        test_app.state.cleanup_task = mock_task

        with patch("src.main.stats") as mock_stats:
            mock_stats.close = AsyncMock()
            await shutdown_logic(test_app)


# ============================================================================
# validate_connections tests
# ============================================================================


class TestValidateConnections:
    """Test validate_connections function."""

    @pytest.mark.asyncio
    async def test_validate_empty_connections(self):
        """Test validation with empty connection config."""
        from src.main import validate_connections

        await validate_connections({})

    @pytest.mark.asyncio
    async def test_validate_none_connection_details(self):
        """Test validation with None connection details."""
        from src.main import validate_connections

        await validate_connections({"conn1": None, "conn2": {"type": "unknown"}})

    @pytest.mark.asyncio
    async def test_validate_unknown_connection_type(self):
        """Test validation with unknown connection type."""
        from src.main import validate_connections

        await validate_connections(
            {"my_conn": {"type": "unknown_type", "host": "example.com", "port": 1234}}
        )

    @pytest.mark.asyncio
    async def test_validate_connection_timeout(self):
        """Test validation handles connection timeout."""
        from src.main import validate_connections

        with patch("src.config._validate_connection_host", return_value="pg.example.com"), patch(
            "src.config._validate_connection_port", return_value=5432
        ), patch("asyncio.wait_for", new_callable=AsyncMock) as mock_wait:
            mock_wait.side_effect = asyncio.TimeoutError()

            await validate_connections(
                {
                    "pg_conn": {
                        "type": "postgresql",
                        "host": "pg.example.com",
                        "port": 5432,
                    }
                }
            )

    @pytest.mark.asyncio
    async def test_validate_postgresql_host_validation_failure(self):
        """Test PostgreSQL host validation failure."""
        from src.main import validate_connections

        with patch(
            "src.config._validate_connection_host",
            side_effect=ValueError("Host not allowed"),
        ):
            await validate_connections(
                {
                    "pg_conn": {
                        "type": "postgresql",
                        "host": "127.0.0.1",
                        "port": 5432,
                    }
                }
            )

    @pytest.mark.asyncio
    async def test_validate_postgresql_port_validation_failure(self):
        """Test PostgreSQL port validation failure."""
        from src.main import validate_connections

        with patch("src.config._validate_connection_host", return_value="pg.example.com"), patch(
            "src.config._validate_connection_port",
            side_effect=ValueError("Port invalid"),
        ):
            await validate_connections(
                {
                    "pg_conn": {
                        "type": "postgresql",
                        "host": "pg.example.com",
                        "port": 99999,
                    }
                }
            )

    @pytest.mark.asyncio
    async def test_validate_mysql_host_validation_failure(self):
        """Test MySQL host validation failure."""
        from src.main import validate_connections

        with patch(
            "src.config._validate_connection_host",
            side_effect=ValueError("Host not allowed"),
        ):
            await validate_connections(
                {
                    "mysql_conn": {
                        "type": "mysql",
                        "host": "127.0.0.1",
                        "port": 3306,
                    }
                }
            )

    @pytest.mark.asyncio
    async def test_validate_redis_host_validation_failure(self):
        """Test Redis host validation failure."""
        from src.main import validate_connections

        with patch(
            "src.config._validate_connection_host",
            side_effect=ValueError("Host not allowed"),
        ):
            await validate_connections(
                {
                    "redis_conn": {
                        "type": "redis-rq",
                        "host": "127.0.0.1",
                        "port": 6379,
                    }
                }
            )

    @pytest.mark.asyncio
    async def test_validate_rabbitmq_port_validation_failure(self):
        """Test RabbitMQ port validation failure."""
        from src.main import validate_connections

        with patch("src.config._validate_connection_host", return_value="rmq.example.com"), patch(
            "src.config._validate_connection_port",
            side_effect=ValueError("Port invalid"),
        ):
            await validate_connections(
                {
                    "rmq_conn": {
                        "type": "rabbitmq",
                        "host": "rmq.example.com",
                        "port": 0,
                    }
                }
            )

    @pytest.mark.asyncio
    async def test_validate_clickhouse_host_validation_failure(self):
        """Test ClickHouse host validation failure."""
        from src.main import validate_connections

        with patch(
            "src.config._validate_connection_host",
            side_effect=ValueError("Host not allowed"),
        ):
            await validate_connections(
                {
                    "ch_conn": {
                        "type": "clickhouse",
                        "host": "127.0.0.1",
                        "port": 9000,
                    }
                }
            )

    @pytest.mark.asyncio
    async def test_validate_kafka_invalid_port(self):
        """Test Kafka bootstrap_servers with invalid port."""
        from src.main import validate_connections

        with patch("src.config._validate_connection_host", return_value="kafka.example.com"), patch(
            "src.config._validate_connection_port",
            side_effect=ValueError("Port invalid"),
        ):
            await validate_connections(
                {
                    "kafka_conn": {
                        "type": "kafka",
                        "bootstrap_servers": "kafka.example.com:99999",
                    }
                }
            )

    @pytest.mark.asyncio
    async def test_validate_kafka_host_validation_failure(self):
        """Test Kafka bootstrap_servers host validation failure."""
        from src.main import validate_connections

        with patch(
            "src.config._validate_connection_host",
            side_effect=ValueError("Host not allowed"),
        ), patch("src.config._validate_connection_port", return_value=9092):
            await validate_connections(
                {
                    "kafka_conn": {
                        "type": "kafka",
                        "bootstrap_servers": "bad-host:9092",
                    }
                }
            )

    @pytest.mark.asyncio
    async def test_validate_connection_sensitive_error_sanitization(self):
        """Test that sensitive info in error messages is redacted."""
        from src.main import validate_connections

        with patch("src.config._validate_connection_host", return_value="pg.example.com"), patch(
            "src.config._validate_connection_port", return_value=5432
        ), patch("asyncio.wait_for", new_callable=AsyncMock) as mock_wait:
            mock_wait.side_effect = Exception(
                "postgresql://user:password@host:5432/db connection failed"
            )

            await validate_connections(
                {
                    "pg_conn": {
                        "type": "postgresql",
                        "host": "pg.example.com",
                        "port": 5432,
                    }
                }
            )


# ============================================================================
# Admin endpoint tests
# ============================================================================


class TestRequireAdminToken:
    """Test _require_admin_token function."""

    def test_admin_token_not_configured(self):
        """Test that admin endpoints return 403 when token is not set."""
        from src.main import _require_admin_token

        mock_request = MagicMock()
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": ""}):
            with pytest.raises(HTTPException) as exc_info:
                _require_admin_token(mock_request)
            assert exc_info.value.status_code == 403

    def test_admin_token_whitespace_only(self):
        """Test that whitespace-only admin token is treated as unconfigured."""
        from src.main import _require_admin_token

        mock_request = MagicMock()
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "   "}):
            with pytest.raises(HTTPException) as exc_info:
                _require_admin_token(mock_request)
            assert exc_info.value.status_code == 403

    def test_admin_missing_auth_header(self):
        """Test that missing auth header returns 401."""
        from src.main import _require_admin_token

        mock_request = MagicMock()
        mock_request.headers.get.return_value = ""
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "secret-token"}):
            with pytest.raises(HTTPException) as exc_info:
                _require_admin_token(mock_request)
            assert exc_info.value.status_code == 401

    def test_admin_header_injection_newline(self):
        """Test that header injection via newlines is blocked."""
        from src.main import _require_admin_token

        mock_request = MagicMock()
        mock_request.headers.get.return_value = "Bearer token\nInjection"
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "secret-token"}):
            with pytest.raises(HTTPException) as exc_info:
                _require_admin_token(mock_request)
            assert exc_info.value.status_code == 401
            assert "Invalid authentication header" in exc_info.value.detail

    def test_admin_header_injection_null_byte(self):
        """Test that header injection via null bytes is blocked."""
        from src.main import _require_admin_token

        mock_request = MagicMock()
        mock_request.headers.get.return_value = "Bearer token\x00evil"
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "secret-token"}):
            with pytest.raises(HTTPException) as exc_info:
                _require_admin_token(mock_request)
            assert exc_info.value.status_code == 401

    def test_admin_whitespace_only_token_in_header(self):
        """Test that whitespace-only token in auth header is rejected."""
        from src.main import _require_admin_token

        mock_request = MagicMock()
        mock_request.headers.get.return_value = "Bearer    "
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "secret-token"}):
            with pytest.raises(HTTPException) as exc_info:
                _require_admin_token(mock_request)
            assert exc_info.value.status_code == 401

    def test_admin_invalid_token(self):
        """Test that wrong token returns 401."""
        from src.main import _require_admin_token

        mock_request = MagicMock()
        mock_request.headers.get.return_value = "Bearer wrong-token"
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "secret-token"}):
            with pytest.raises(HTTPException) as exc_info:
                _require_admin_token(mock_request)
            assert exc_info.value.status_code == 401

    def test_admin_valid_token_with_bearer(self):
        """Test that valid Bearer token passes."""
        from src.main import _require_admin_token

        mock_request = MagicMock()
        mock_request.headers.get.return_value = "Bearer secret-token"
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "secret-token"}):
            # Should not raise
            _require_admin_token(mock_request)

    def test_admin_valid_token_without_bearer(self):
        """Test that valid token without Bearer prefix passes."""
        from src.main import _require_admin_token

        mock_request = MagicMock()
        mock_request.headers.get.return_value = "secret-token"
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "secret-token"}):
            _require_admin_token(mock_request)


# ============================================================================
# Route handler tests (using httpx/TestClient)
# ============================================================================


class TestWebhookEndpointRetry:
    """Test webhook route handler retry paths."""

    @pytest.mark.asyncio
    async def test_webhook_retry_task_done_success(self):
        """Test webhook endpoint when retry task completes successfully."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        mock_task = MagicMock()
        mock_task.done.return_value = True
        mock_task.result.return_value = (True, None)

        mock_handler = MagicMock()
        mock_handler.validate_webhook = AsyncMock(return_value=(True, "Valid"))
        mock_handler.process_webhook = AsyncMock(
            return_value=({"test": "data"}, {}, mock_task)
        )
        mock_handler.config = {"retry": {"enabled": True}}

        with patch("src.main.WebhookHandler", return_value=mock_handler), patch(
            "src.main.stats"
        ) as mock_stats:
            mock_stats.increment = AsyncMock()
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.post("/webhook/test_wh", json={"key": "value"})
                assert response.status_code == 200
                data = response.json()
                assert data["status"] == "processed"

    @pytest.mark.asyncio
    async def test_webhook_retry_task_done_failure(self):
        """Test webhook endpoint when retry task completes with failure."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        mock_task = MagicMock()
        mock_task.done.return_value = True
        mock_task.result.return_value = (False, Exception("Module failed"))

        mock_handler = MagicMock()
        mock_handler.validate_webhook = AsyncMock(return_value=(True, "Valid"))
        mock_handler.process_webhook = AsyncMock(
            return_value=({"test": "data"}, {}, mock_task)
        )
        mock_handler.config = {"retry": {"enabled": True}}

        with patch("src.main.WebhookHandler", return_value=mock_handler), patch(
            "src.main.stats"
        ) as mock_stats:
            mock_stats.increment = AsyncMock()
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.post("/webhook/test_wh", json={"key": "value"})
                assert response.status_code == 202
                data = response.json()
                assert data["status"] == "accepted"

    @pytest.mark.asyncio
    async def test_webhook_retry_task_exception(self):
        """Test webhook endpoint when retry task raises exception."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        mock_task = MagicMock()
        mock_task.done.return_value = True
        mock_task.result.side_effect = Exception("Task error")

        mock_handler = MagicMock()
        mock_handler.validate_webhook = AsyncMock(return_value=(True, "Valid"))
        mock_handler.process_webhook = AsyncMock(
            return_value=({"test": "data"}, {}, mock_task)
        )
        mock_handler.config = {"retry": {"enabled": True}}

        with patch("src.main.WebhookHandler", return_value=mock_handler), patch(
            "src.main.stats"
        ) as mock_stats:
            mock_stats.increment = AsyncMock()
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.post("/webhook/test_wh", json={"key": "value"})
                assert response.status_code == 202

    @pytest.mark.asyncio
    async def test_webhook_retry_task_still_running(self):
        """Test webhook endpoint when retry task is still running."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        mock_task = MagicMock()
        mock_task.done.return_value = False

        mock_handler = MagicMock()
        mock_handler.validate_webhook = AsyncMock(return_value=(True, "Valid"))
        mock_handler.process_webhook = AsyncMock(
            return_value=({"test": "data"}, {}, mock_task)
        )
        mock_handler.config = {"retry": {"enabled": True}}

        with patch("src.main.WebhookHandler", return_value=mock_handler), patch(
            "src.main.stats"
        ) as mock_stats:
            mock_stats.increment = AsyncMock()
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.post("/webhook/test_wh", json={"key": "value"})
                assert response.status_code == 202
                data = response.json()
                assert data["status"] == "accepted"


class TestNamespacedWebhookEndpoint:
    """Test namespaced webhook route handler."""

    @pytest.mark.asyncio
    async def test_namespaced_webhook_invalid_namespace(self):
        """Test namespaced webhook with invalid namespace format."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            # Namespace with special characters should be rejected
            response = await ac.post(
                "/webhook/invalid$namespace/test_wh", json={"key": "value"}
            )
            assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_namespaced_webhook_success(self):
        """Test namespaced webhook with valid namespace."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        mock_handler = MagicMock()
        mock_handler.validate_webhook = AsyncMock(return_value=(True, "Valid"))
        mock_handler.process_webhook = AsyncMock(
            return_value=({"test": "data"}, {}, None)
        )
        mock_handler.config = {}

        with patch("src.main.WebhookHandler", return_value=mock_handler), patch(
            "src.main.stats"
        ) as mock_stats:
            mock_stats.increment = AsyncMock()
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.post(
                    "/webhook/staging/test_wh", json={"key": "value"}
                )
                assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_namespaced_webhook_validation_failure(self):
        """Test namespaced webhook with authorization failure."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        mock_handler = MagicMock()
        mock_handler.validate_webhook = AsyncMock(return_value=(False, "Unauthorized"))
        mock_handler.config = {}

        with patch("src.main.WebhookHandler", return_value=mock_handler):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.post(
                    "/webhook/staging/test_wh", json={"key": "value"}
                )
                assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_namespaced_webhook_handler_init_exception(self):
        """Test namespaced webhook when handler init raises generic exception."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        with patch(
            "src.main.WebhookHandler", side_effect=Exception("Unexpected init error")
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.post(
                    "/webhook/staging/test_wh", json={"key": "value"}
                )
                assert response.status_code == 500

    @pytest.mark.asyncio
    async def test_namespaced_webhook_process_exception(self):
        """Test namespaced webhook when process_webhook raises generic exception."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        mock_handler = MagicMock()
        mock_handler.validate_webhook = AsyncMock(return_value=(True, "Valid"))
        mock_handler.process_webhook = AsyncMock(
            side_effect=Exception("Processing error")
        )
        mock_handler.config = {}

        with patch("src.main.WebhookHandler", return_value=mock_handler):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.post(
                    "/webhook/staging/test_wh", json={"key": "value"}
                )
                assert response.status_code == 500

    @pytest.mark.asyncio
    async def test_namespaced_webhook_retry_task_done_success(self):
        """Test namespaced webhook with retry task completed successfully."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        mock_task = MagicMock()
        mock_task.done.return_value = True
        mock_task.result.return_value = (True, None)

        mock_handler = MagicMock()
        mock_handler.validate_webhook = AsyncMock(return_value=(True, "Valid"))
        mock_handler.process_webhook = AsyncMock(
            return_value=({"test": "data"}, {}, mock_task)
        )
        mock_handler.config = {"retry": {"enabled": True}}

        with patch("src.main.WebhookHandler", return_value=mock_handler), patch(
            "src.main.stats"
        ) as mock_stats:
            mock_stats.increment = AsyncMock()
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.post(
                    "/webhook/staging/test_wh", json={"key": "value"}
                )
                assert response.status_code == 200
                data = response.json()
                assert data["status"] == "processed"

    @pytest.mark.asyncio
    async def test_namespaced_webhook_retry_task_done_failure(self):
        """Test namespaced webhook with retry task completed with failure."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        mock_task = MagicMock()
        mock_task.done.return_value = True
        mock_task.result.return_value = (False, Exception("Failed"))

        mock_handler = MagicMock()
        mock_handler.validate_webhook = AsyncMock(return_value=(True, "Valid"))
        mock_handler.process_webhook = AsyncMock(
            return_value=({"test": "data"}, {}, mock_task)
        )
        mock_handler.config = {"retry": {"enabled": True}}

        with patch("src.main.WebhookHandler", return_value=mock_handler), patch(
            "src.main.stats"
        ) as mock_stats:
            mock_stats.increment = AsyncMock()
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.post(
                    "/webhook/staging/test_wh", json={"key": "value"}
                )
                assert response.status_code == 202


class TestStatsEndpoint:
    """Test stats endpoint."""

    @pytest.mark.asyncio
    async def test_stats_with_auth_token_missing(self):
        """Test stats endpoint returns 401 when auth token is required but missing."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        with patch.dict(os.environ, {"STATS_AUTH_TOKEN": "my-secret-stats-token"}):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.get("/stats")
                assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_stats_with_auth_token_invalid(self):
        """Test stats endpoint returns 401 with wrong auth token."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        with patch.dict(os.environ, {"STATS_AUTH_TOKEN": "my-secret-stats-token"}):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.get(
                    "/stats", headers={"Authorization": "Bearer wrong-token"}
                )
                assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_stats_with_auth_token_valid(self):
        """Test stats endpoint passes with correct auth token."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        with patch.dict(os.environ, {"STATS_AUTH_TOKEN": "my-secret-stats-token"}), patch(
            "src.main.stats"
        ) as mock_stats, patch(
            "src.main.rate_limiter"
        ) as mock_rl:
            mock_stats.get_stats = AsyncMock(return_value={"wh1": {"count": 10}})
            mock_rl.check_rate_limit = AsyncMock(return_value=(True, 59))
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.get(
                    "/stats",
                    headers={"Authorization": "Bearer my-secret-stats-token"},
                )
                assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_stats_ip_whitelist_denied(self):
        """Test stats endpoint denies non-whitelisted IPs."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        with patch.dict(
            os.environ, {"STATS_ALLOWED_IPS": "10.0.0.1,10.0.0.2"}
        ), patch("src.main.get_client_ip", return_value=("192.168.1.1", False)):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.get("/stats")
                assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_stats_rate_limit_exceeded(self):
        """Test stats endpoint returns 429 when rate limited."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        with patch("src.main.rate_limiter") as mock_rl, patch(
            "src.main.get_client_ip", return_value=("10.0.0.1", False)
        ):
            mock_rl.check_rate_limit = AsyncMock(return_value=(False, 0))
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.get("/stats")
                assert response.status_code == 429

    @pytest.mark.asyncio
    async def test_stats_sanitize_ids(self):
        """Test stats endpoint with STATS_SANITIZE_IDS enabled."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        with patch.dict(os.environ, {"STATS_SANITIZE_IDS": "true"}), patch(
            "src.main.stats"
        ) as mock_stats, patch("src.main.rate_limiter") as mock_rl:
            mock_stats.get_stats = AsyncMock(return_value={"my_webhook": {"count": 5}})
            mock_rl.check_rate_limit = AsyncMock(return_value=(True, 59))
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.get("/stats")
                assert response.status_code == 200
                data = response.json()
                # Should have hashed keys
                keys = list(data.keys())
                assert all(k.startswith("webhook_") for k in keys)


class TestHealthEndpoint:
    """Test health endpoint paths."""

    @pytest.mark.asyncio
    async def test_health_config_manager_unhealthy(self):
        """Test health endpoint when config manager is unhealthy."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        mock_cm = MagicMock()
        mock_cm.get_all_webhook_configs.side_effect = Exception("Config error")
        app.state.config_manager = mock_cm

        with patch("src.main.stats") as mock_stats:
            mock_stats.get_stats = AsyncMock(return_value={})
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.get("/health")
                assert response.status_code == 503
                data = response.json()
                assert data["status"] == "unhealthy"
                assert data["components"]["config_manager"] == "unhealthy"

    @pytest.mark.asyncio
    async def test_health_no_config_manager(self):
        """Test health endpoint without config manager."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        app.state.config_manager = None

        with patch("src.main.stats") as mock_stats:
            mock_stats.get_stats = AsyncMock(return_value={})
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.get("/health")
                assert response.status_code == 200
                data = response.json()
                assert data["components"]["config_manager"] == "not_configured"

    @pytest.mark.asyncio
    async def test_health_clickhouse_disconnected(self):
        """Test health endpoint with ClickHouse disconnected."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        app.state.config_manager = None
        mock_ch = MagicMock()
        mock_ch.client = None
        app.state.clickhouse_logger = mock_ch

        with patch("src.main.stats") as mock_stats:
            mock_stats.get_stats = AsyncMock(return_value={})
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.get("/health")
                data = response.json()
                assert data["components"]["clickhouse"] == "disconnected"

    @pytest.mark.asyncio
    async def test_health_webhook_connect_running(self):
        """Test health endpoint with Webhook Connect running."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        app.state.config_manager = None
        app.state.clickhouse_logger = None
        mock_wc = MagicMock()
        mock_wc.is_running.return_value = True
        app.state.webhook_connect_channel_manager = mock_wc

        with patch("src.main.stats") as mock_stats:
            mock_stats.get_stats = AsyncMock(return_value={})
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.get("/health")
                data = response.json()
                assert data["components"]["webhook_connect"] == "healthy"

    @pytest.mark.asyncio
    async def test_health_webhook_connect_degraded(self):
        """Test health endpoint with Webhook Connect degraded."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        app.state.config_manager = None
        app.state.clickhouse_logger = None
        mock_wc = MagicMock()
        mock_wc.is_running.return_value = False
        app.state.webhook_connect_channel_manager = mock_wc

        with patch("src.main.stats") as mock_stats:
            mock_stats.get_stats = AsyncMock(return_value={})
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.get("/health")
                data = response.json()
                assert data["components"]["webhook_connect"] == "degraded"

    @pytest.mark.asyncio
    async def test_health_etcd_provider_status(self):
        """Test health endpoint with etcd provider status."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        mock_cm = MagicMock()
        mock_cm.get_all_webhook_configs.return_value = {}
        mock_provider = MagicMock()
        mock_provider.get_status.return_value = {"backend": "etcd", "connected": True}
        mock_cm.provider = mock_provider
        app.state.config_manager = mock_cm
        app.state.clickhouse_logger = None
        app.state.webhook_connect_channel_manager = None

        with patch("src.main.stats") as mock_stats:
            mock_stats.get_stats = AsyncMock(return_value={})
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.get("/health")
                data = response.json()
                assert data["components"]["etcd"] == "healthy"

    @pytest.mark.asyncio
    async def test_health_etcd_provider_disconnected(self):
        """Test health endpoint with etcd provider disconnected."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        mock_cm = MagicMock()
        mock_cm.get_all_webhook_configs.return_value = {}
        mock_provider = MagicMock()
        mock_provider.get_status.return_value = {"backend": "etcd", "connected": False}
        mock_cm.provider = mock_provider
        app.state.config_manager = mock_cm
        app.state.clickhouse_logger = None
        app.state.webhook_connect_channel_manager = None

        with patch("src.main.stats") as mock_stats:
            mock_stats.get_stats = AsyncMock(return_value={})
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.get("/health")
                data = response.json()
                assert data["components"]["etcd"] == "disconnected"

    @pytest.mark.asyncio
    async def test_health_non_etcd_backend(self):
        """Test health endpoint with non-etcd backend in provider status."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        mock_cm = MagicMock()
        mock_cm.get_all_webhook_configs.return_value = {}
        mock_provider = MagicMock()
        mock_provider.get_status.return_value = {"backend": "file"}
        mock_cm.provider = mock_provider
        app.state.config_manager = mock_cm
        app.state.clickhouse_logger = None
        app.state.webhook_connect_channel_manager = None

        with patch("src.main.stats") as mock_stats:
            mock_stats.get_stats = AsyncMock(return_value={})
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.get("/health")
                data = response.json()
                assert data["components"]["config_backend"] == "file"


class TestDefaultEndpoint:
    """Test default root endpoint."""

    @pytest.mark.asyncio
    async def test_default_rate_limit_exceeded(self):
        """Test default endpoint returns 429 when rate limited."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        with patch("src.main.rate_limiter") as mock_rl, patch(
            "src.main.get_client_ip", return_value=("10.0.0.1", False)
        ):
            mock_rl.check_rate_limit = AsyncMock(return_value=(False, 0))
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.get("/")
                assert response.status_code == 429


class TestReloadConfigEndpoint:
    """Test admin reload config endpoint."""

    @pytest.mark.asyncio
    async def test_reload_no_config_manager(self):
        """Test reload returns 503 when ConfigManager not initialized."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        app.state.config_manager = None

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.post("/admin/reload-config")
            assert response.status_code == 503

    @pytest.mark.asyncio
    async def test_reload_webhooks_only(self):
        """Test reloading only webhooks."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        mock_cm = MagicMock()
        mock_result = Mock(
            success=True,
            details={"total_webhooks": 3},
            timestamp="2026-01-01T00:00:00Z",
        )
        mock_cm.reload_webhooks = AsyncMock(return_value=mock_result)
        app.state.config_manager = mock_cm

        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "test-token"}):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.post(
                    "/admin/reload-config",
                    json={"reload_webhooks": True, "reload_connections": False},
                    headers={"Authorization": "Bearer test-token"},
                )
                assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_reload_connections_only(self):
        """Test reloading only connections."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        mock_cm = MagicMock()
        mock_result = Mock(
            success=True,
            details={"total_connections": 2},
            timestamp="2026-01-01T00:00:00Z",
        )
        mock_cm.reload_connections = AsyncMock(return_value=mock_result)
        app.state.config_manager = mock_cm

        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "test-token"}):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.post(
                    "/admin/reload-config",
                    json={"reload_webhooks": False, "reload_connections": True},
                    headers={"Authorization": "Bearer test-token"},
                )
                assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_reload_neither(self):
        """Test reload endpoint when neither flag is set."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        mock_cm = MagicMock()
        app.state.config_manager = mock_cm

        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "test-token"}):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.post(
                    "/admin/reload-config",
                    json={"reload_webhooks": False, "reload_connections": False},
                    headers={"Authorization": "Bearer test-token"},
                )
                assert response.status_code == 200
                data = response.json()
                assert data["status"] == "error"

    @pytest.mark.asyncio
    async def test_reload_validate_only(self):
        """Test reload endpoint with validate_only flag."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        mock_cm = MagicMock()
        app.state.config_manager = mock_cm

        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "test-token"}):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.post(
                    "/admin/reload-config",
                    json={"validate_only": True},
                    headers={"Authorization": "Bearer test-token"},
                )
                assert response.status_code == 200
                data = response.json()
                assert data["status"] == "validation_not_implemented"

    @pytest.mark.asyncio
    async def test_reload_failure_with_sanitized_error(self):
        """Test reload endpoint when reload fails."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        mock_cm = MagicMock()
        mock_result = Mock(
            success=False,
            error="Failed to reload: file not found",
            details={"file_path": "/etc/secret/webhooks.json"},
            timestamp="2026-01-01T00:00:00Z",
        )
        mock_cm.reload_all = AsyncMock(return_value=mock_result)
        app.state.config_manager = mock_cm

        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "test-token"}):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.post(
                    "/admin/reload-config",
                    headers={"Authorization": "Bearer test-token"},
                )
                assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_reload_success_with_sensitive_details_redacted(self):
        """Test reload response redacts sensitive information in details."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        mock_cm = MagicMock()
        mock_result = Mock(
            success=True,
            details={
                "total_webhooks": 3,
                "password": "secret123",
                "info": "connected to postgresql://user:pass@host/db",
            },
            timestamp="2026-01-01T00:00:00Z",
        )
        mock_cm.reload_all = AsyncMock(return_value=mock_result)
        app.state.config_manager = mock_cm

        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "test-token"}):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.post(
                    "/admin/reload-config",
                    headers={"Authorization": "Bearer test-token"},
                )
                assert response.status_code == 200
                data = response.json()
                # password key should be removed entirely
                assert "password" not in data["details"]
                # sensitive values should be redacted
                assert data["details"]["info"] == "[REDACTED]"

    @pytest.mark.asyncio
    async def test_reload_with_invalid_json_body(self):
        """Test reload endpoint with invalid request body (defaults to reload both)."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        mock_cm = MagicMock()
        mock_result = Mock(
            success=True,
            details={"total_webhooks": 3},
            timestamp="2026-01-01T00:00:00Z",
        )
        mock_cm.reload_all = AsyncMock(return_value=mock_result)
        app.state.config_manager = mock_cm

        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "test-token"}):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.post(
                    "/admin/reload-config",
                    content="not-valid-json",
                    headers={
                        "Authorization": "Bearer test-token",
                        "Content-Type": "application/json",
                    },
                )
                assert response.status_code == 200


class TestConfigStatusEndpoint:
    """Test admin config status endpoint."""

    @pytest.mark.asyncio
    async def test_config_status_no_config_manager(self):
        """Test config status returns 503 when ConfigManager not initialized."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        app.state.config_manager = None

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.get("/admin/config-status")
            assert response.status_code == 503

    @pytest.mark.asyncio
    async def test_config_status_with_file_watcher(self):
        """Test config status includes file watcher status."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        mock_cm = MagicMock()
        mock_cm.get_status.return_value = {
            "last_reload": None,
            "reload_in_progress": False,
            "webhooks_count": 2,
            "connections_count": 1,
            "connection_pools": {"active": 0, "deprecated": 0},
            "pool_details": {},
        }
        app.state.config_manager = mock_cm
        mock_watcher = MagicMock()
        mock_watcher.is_watching.return_value = True
        app.state.config_watcher = mock_watcher

        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "test-token"}):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.get(
                    "/admin/config-status",
                    headers={"Authorization": "Bearer test-token"},
                )
                assert response.status_code == 200
                data = response.json()
                assert data["file_watching_enabled"] is True

    @pytest.mark.asyncio
    async def test_config_status_sanitizes_pool_details(self):
        """Test config status sanitizes sensitive pool details."""
        from httpx import AsyncClient, ASGITransport
        from src.main import app

        mock_cm = MagicMock()
        mock_cm.get_status.return_value = {
            "last_reload": None,
            "reload_in_progress": False,
            "webhooks_count": 1,
            "connections_count": 1,
            "connection_pools": {"active": 1, "deprecated": 0},
            "pool_details": {
                "my_db": {
                    "host": "db.example.com",
                    "password": "secret123",
                    "connection_string": "postgresql://user:pass@host/db",
                    "info": "connected to postgresql://user:pass@host/db",
                }
            },
        }
        app.state.config_manager = mock_cm
        app.state.config_watcher = None

        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "test-token"}):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.get(
                    "/admin/config-status",
                    headers={"Authorization": "Bearer test-token"},
                )
                assert response.status_code == 200
                data = response.json()
                pool = data["pool_details"]["my_db"]
                assert "password" not in pool
                assert "connection_string" not in pool
                assert pool["info"] == "[REDACTED]"
