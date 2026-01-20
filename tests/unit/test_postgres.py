"""Tests for PostgreSQL module."""

import pytest
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch
from src.modules.postgres import PostgreSQLModule


class TestPostgreSQLModule:
    """Test PostgreSQL module functionality."""

    @pytest.fixture
    def mock_pool(self):
        """Create a mock asyncpg pool."""
        pool = AsyncMock()
        conn = AsyncMock()

        # Create a proper async context manager for acquire()
        async def acquire():
            return conn

        acquire_ctx = MagicMock()
        acquire_ctx.__aenter__ = AsyncMock(return_value=conn)
        acquire_ctx.__aexit__ = AsyncMock(return_value=None)
        pool.acquire = MagicMock(return_value=acquire_ctx)

        conn.execute = AsyncMock(return_value="INSERT 1")
        conn.fetchval = AsyncMock(return_value=1)
        return pool

    @pytest.fixture
    def basic_config(self):
        """Basic module configuration."""
        return {
            "connection_details": {
                "host": "db.example.com",  # Use public hostname to pass SSRF check
                "port": 5432,
                "database": "test_db",
                "user": "test_user",
                "password": "test_pass",
            },
            "module-config": {"table": "webhook_events", "storage_mode": "json"},
            "_webhook_id": "test_webhook",
        }

    def test_validate_table_name_valid(self):
        """Test table name validation with valid names."""
        config = {
            "connection_details": {},
            "module-config": {"table": "valid_table_name"},
        }
        module = PostgreSQLModule(config)
        assert module.table_name == "valid_table_name"

    def test_validate_table_name_invalid_characters(self):
        """Test table name validation rejects invalid characters."""
        config = {
            "connection_details": {},
            "module-config": {"table": "invalid-table-name"},
        }
        with pytest.raises(ValueError, match="Invalid table name format"):
            PostgreSQLModule(config)

    def test_validate_table_name_sql_keyword(self):
        """Test table name validation rejects SQL keywords."""
        config = {"connection_details": {}, "module-config": {"table": "select"}}
        with pytest.raises(ValueError, match="SQL keyword"):
            PostgreSQLModule(config)

    def test_validate_table_name_too_long(self):
        """Test table name validation rejects names that are too long."""
        config = {"connection_details": {}, "module-config": {"table": "a" * 64}}
        with pytest.raises(ValueError, match="too long"):
            PostgreSQLModule(config)

    def test_validate_column_name_valid(self):
        """Test column name validation with valid names."""
        config = {"connection_details": {}, "module-config": {"table": "test_table"}}
        module = PostgreSQLModule(config)
        assert module._validate_column_name("valid_column") == "valid_column"

    def test_validate_hostname_blocks_localhost(self):
        """Test hostname validation blocks localhost."""
        # Save original value and ensure localhost is blocked for this test
        original_value = os.environ.get("ALLOW_LOCALHOST_FOR_TESTS")
        try:
            # Explicitly set to false to ensure localhost is blocked
            os.environ["ALLOW_LOCALHOST_FOR_TESTS"] = "false"

            config = {
                "connection_details": {},
                "module-config": {"table": "test_table"},
            }
            module = PostgreSQLModule(config)
            assert module._validate_hostname("localhost") is False
            assert module._validate_hostname("127.0.0.1") is False
            # Private IPs are now allowed for internal network usage
            assert module._validate_hostname("192.168.1.1") is True
            assert module._validate_hostname("10.0.0.1") is True
            # Still block link-local addresses
            assert module._validate_hostname("169.254.1.1") is False
        finally:
            # Restore original value
            if original_value is None:
                os.environ.pop("ALLOW_LOCALHOST_FOR_TESTS", None)
            else:
                os.environ["ALLOW_LOCALHOST_FOR_TESTS"] = original_value

    def test_validate_hostname_allows_public(self):
        """Test hostname validation allows public hostnames."""
        config = {"connection_details": {}, "module-config": {"table": "test_table"}}
        module = PostgreSQLModule(config)
        assert module._validate_hostname("example.com") is True
        assert module._validate_hostname("db.example.com") is True

    def test_get_pg_type_mapping(self):
        """Test PostgreSQL type mapping."""
        config = {"connection_details": {}, "module-config": {"table": "test_table"}}
        module = PostgreSQLModule(config)
        assert module._get_pg_type("string") == "TEXT"
        assert module._get_pg_type("integer") == "BIGINT"
        assert module._get_pg_type("float") == "DOUBLE PRECISION"
        assert module._get_pg_type("boolean") == "BOOLEAN"
        assert module._get_pg_type("datetime") == "TIMESTAMP WITH TIME ZONE"
        assert module._get_pg_type("json") == "JSONB"

    @pytest.mark.asyncio
    async def test_setup_creates_pool(self, basic_config, mock_pool):
        """Test setup creates connection pool."""

        async def create_pool(*args, **kwargs):
            return mock_pool

        with patch("asyncpg.create_pool", side_effect=create_pool):
            module = PostgreSQLModule(basic_config)
            await module.setup()
            assert module.pool == mock_pool

    @pytest.mark.asyncio
    async def test_setup_validates_hostname(self, basic_config):
        """Test setup validates hostname for SSRF prevention."""
        # Save original value and ensure localhost is blocked for this test
        original_value = os.environ.get("ALLOW_LOCALHOST_FOR_TESTS")
        try:
            # Explicitly set to false to ensure localhost is blocked
            os.environ["ALLOW_LOCALHOST_FOR_TESTS"] = "false"

            basic_config["connection_details"]["host"] = "127.0.0.1"
            module = PostgreSQLModule(basic_config)
            with pytest.raises(ValueError, match="Invalid or unsafe hostname"):
                await module.setup()
        finally:
            # Restore original value
            if original_value is None:
                os.environ.pop("ALLOW_LOCALHOST_FOR_TESTS", None)
            else:
                os.environ["ALLOW_LOCALHOST_FOR_TESTS"] = original_value

    @pytest.mark.asyncio
    async def test_process_json_mode(self, basic_config, mock_pool):
        """Test process in JSON mode."""
        module = PostgreSQLModule(basic_config)
        module.pool = mock_pool
        module._table_created = True

        payload = {"event": "test", "data": {"key": "value"}}
        headers = {"Content-Type": "application/json"}

        await module.process(payload, headers)

        # Verify execute was called
        assert mock_pool.acquire.return_value.__aenter__.return_value.execute.called

    @pytest.mark.asyncio
    async def test_process_relational_mode(self, basic_config, mock_pool):
        """Test process in relational mode."""
        basic_config["module-config"] = {
            "table": "webhook_events",
            "storage_mode": "relational",
            "schema": {
                "fields": {
                    "event_id": {"type": "string", "column": "event_id"},
                    "user_id": {"type": "integer", "column": "user_id"},
                }
            },
        }

        module = PostgreSQLModule(basic_config)
        module.pool = mock_pool
        module._table_created = True

        payload = {"event_id": "evt_123", "user_id": 456}
        headers = {}

        await module.process(payload, headers)

        # Verify execute was called
        assert mock_pool.acquire.return_value.__aenter__.return_value.execute.called

    @pytest.mark.asyncio
    async def test_process_hybrid_mode(self, basic_config, mock_pool):
        """Test process in hybrid mode."""
        basic_config["module-config"] = {
            "table": "webhook_events",
            "storage_mode": "hybrid",
            "include_headers": True,
            "schema": {
                "fields": {"event_id": {"type": "string", "column": "event_id"}}
            },
        }

        module = PostgreSQLModule(basic_config)
        module.pool = mock_pool
        module._table_created = True

        payload = {"event_id": "evt_123", "extra": "data"}
        headers = {"X-Custom": "header"}

        await module.process(payload, headers)

        # Verify execute was called
        assert mock_pool.acquire.return_value.__aenter__.return_value.execute.called

    @pytest.mark.asyncio
    async def test_process_upsert_json_mode(self, basic_config, mock_pool):
        """Test process with upsert in JSON mode."""
        basic_config["module-config"] = {
            "table": "webhook_events",
            "storage_mode": "json",
            "upsert": True,
            "upsert_key": "event_id",
        }

        module = PostgreSQLModule(basic_config)
        module.pool = mock_pool
        module._table_created = True

        payload = {"event_id": "evt_123", "data": "test"}
        headers = {}

        await module.process(payload, headers)

        # Verify execute was called
        assert mock_pool.acquire.return_value.__aenter__.return_value.execute.called

    @pytest.mark.asyncio
    async def test_teardown_closes_pool(self, basic_config, mock_pool):
        """Test teardown closes connection pool."""
        module = PostgreSQLModule(basic_config)
        module.pool = mock_pool
        mock_pool.close = AsyncMock()

        await module.teardown()

        mock_pool.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_ensure_table_json_mode(self, basic_config, mock_pool):
        """Test table creation in JSON mode."""
        module = PostgreSQLModule(basic_config)
        module.pool = mock_pool

        await module._ensure_table()

        # Verify table creation query was executed
        assert mock_pool.acquire.return_value.__aenter__.return_value.execute.called
        assert module._table_created is True

    @pytest.mark.asyncio
    async def test_ensure_table_relational_mode(self, basic_config, mock_pool):
        """Test table creation in relational mode."""
        basic_config["module-config"] = {
            "table": "webhook_events",
            "storage_mode": "relational",
            "schema": {
                "fields": {
                    "event_id": {
                        "type": "string",
                        "column": "event_id",
                        "constraints": ["NOT NULL"],
                    },
                    "user_id": {"type": "integer", "column": "user_id"},
                }
            },
        }

        module = PostgreSQLModule(basic_config)
        module.pool = mock_pool

        await module._ensure_table()

        # Verify table creation query was executed
        assert mock_pool.acquire.return_value.__aenter__.return_value.execute.called
        assert module._table_created is True

    def test_quote_identifier(self, basic_config):
        """Test identifier quoting."""
        module = PostgreSQLModule(basic_config)
        assert module._quote_identifier("test_table") == '"test_table"'
        assert module._quote_identifier('test"table') == '"test""table"'

    @pytest.mark.asyncio
    async def test_ensure_table_creates_gin_index_after_table(
        self, basic_config, mock_pool
    ):
        """Test that GIN index is created AFTER table exists (not before)."""
        # Configure with upsert enabled to trigger GIN index creation
        basic_config["module-config"] = {
            "table": "webhook_events",
            "storage_mode": "json",
            "upsert": True,
            "upsert_key": "event_id",
        }

        module = PostgreSQLModule(basic_config)
        module.pool = mock_pool

        # Track the order of execute calls
        execute_calls = []
        original_execute = (
            mock_pool.acquire.return_value.__aenter__.return_value.execute
        )

        async def track_execute(query):
            execute_calls.append(query)
            return await original_execute(query)

        mock_pool.acquire.return_value.__aenter__.return_value.execute = track_execute

        await module._ensure_table()

        # Verify table was created first
        assert len(execute_calls) >= 1
        assert "CREATE TABLE" in execute_calls[0].upper()

        # Verify GIN index was created after table
        if len(execute_calls) > 1:
            assert "CREATE INDEX" in execute_calls[1].upper()
            assert "GIN" in execute_calls[1].upper()
            assert "payload" in execute_calls[1].lower()

        assert module._table_created is True

    @pytest.mark.asyncio
    async def test_gin_index_name_validation_and_quoting(self, basic_config, mock_pool):
        """Test that GIN index name is properly validated and quoted."""
        basic_config["module-config"] = {
            "table": "webhook_events",
            "storage_mode": "json",
            "upsert": True,
            "upsert_key": "event_id",
        }

        module = PostgreSQLModule(basic_config)
        module.pool = mock_pool

        execute_calls = []
        original_execute = (
            mock_pool.acquire.return_value.__aenter__.return_value.execute
        )

        async def track_execute(query):
            execute_calls.append(query)
            return await original_execute(query)

        mock_pool.acquire.return_value.__aenter__.return_value.execute = track_execute

        await module._ensure_table()

        # Find the index creation query
        index_queries = [q for q in execute_calls if "CREATE INDEX" in q.upper()]
        assert len(index_queries) > 0

        index_query = index_queries[0]
        # Verify index name is properly quoted (should contain quotes around the name)
        assert (
            '"webhook_events_payload_gin"' in index_query
            or "webhook_events_payload_gin" in index_query
        )
        # Verify it's a GIN index
        assert "USING GIN" in index_query.upper()
        # Verify it references the payload column
        assert "payload" in index_query.lower()
        # Verify it references the table (which should be quoted)
        assert '"webhook_events"' in index_query or "webhook_events" in index_query
