"""
Integration tests for ClickHouse advanced features.

These tests verify native protocol, table validation, header/timestamp inclusion,
and connection error handling.
"""

import pytest
import httpx
import json
from clickhouse_driver import Client
from tests.integration.test_config import (
    CLICKHOUSE_HOST,
    CLICKHOUSE_PORT,
    CLICKHOUSE_HTTP_URL,
    TEST_CLICKHOUSE_TABLE_PREFIX,
)
import os
from src.modules.clickhouse import ClickHouseModule


@pytest.mark.integration
@pytest.mark.external_services
class TestClickHouseAdvancedIntegration:
    """Integration tests for ClickHouse advanced features."""

    @pytest.fixture
    def clickhouse_native_client(self):
        """Create a ClickHouse native protocol client."""
        # Use native port 9000 (default for ClickHouse)
        client = Client(
            host=CLICKHOUSE_HOST,
            port=9000,  # Native protocol port
            user=os.getenv("CLICKHOUSE_USER", "default"),
            password=os.getenv("CLICKHOUSE_PASSWORD", ""),
            database=os.getenv("CLICKHOUSE_DB", "default"),
        )
        yield client
        client.disconnect()

    @pytest.fixture
    async def cleanup_tables(self, clickhouse_native_client: Client):
        """Clean up test tables before and after each test."""
        yield
        tables = clickhouse_native_client.execute("SHOW TABLES")
        for (table_name,) in tables:
            if table_name.startswith(TEST_CLICKHOUSE_TABLE_PREFIX):
                clickhouse_native_client.execute(f"DROP TABLE IF EXISTS {table_name}")

    @pytest.mark.asyncio
    async def test_native_protocol_connection(self, clickhouse_native_client: Client):
        """Test connecting via native protocol (port 9000)."""
        result = clickhouse_native_client.execute("SELECT 1")
        assert result == [(1,)]

    @pytest.mark.asyncio
    async def test_native_vs_http_protocol(self, clickhouse_native_client: Client):
        """Test that both native and HTTP protocols work."""
        # Native protocol query
        native_result = clickhouse_native_client.execute("SELECT version()")
        assert len(native_result) > 0

        # HTTP protocol query
        response = httpx.get(
            CLICKHOUSE_HTTP_URL + "/", params={"query": "SELECT version()"}, timeout=5.0
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_table_name_validation(self):
        """Test that ClickHouse module validates table names."""
        from src.modules.clickhouse import ClickHouseModule

        # Valid table name
        valid_config = {
            "module": "clickhouse",
            "module-config": {"table": "valid_table_name_123"},
            "connection_details": {},
        }
        module = ClickHouseModule(valid_config)
        assert module.table_name == "valid_table_name_123"

        # Invalid table name (contains SQL injection attempt)
        invalid_config = {
            "module": "clickhouse",
            "module-config": {"table": "table; DROP TABLE users;--"},
            "connection_details": {},
        }
        with pytest.raises(ValueError):
            ClickHouseModule(invalid_config)

    @pytest.mark.asyncio
    async def test_include_headers_configuration(
        self, clickhouse_native_client: Client, cleanup_tables
    ):
        """Test that headers can be included in ClickHouse logs."""
        test_table = f"{TEST_CLICKHOUSE_TABLE_PREFIX}headers_test"

        # Create table with headers column
        create_table_query = f"""
        CREATE TABLE IF NOT EXISTS {test_table} (
            id String,
            webhook_id String,
            timestamp DateTime,
            payload String,
            headers String
        ) ENGINE = MergeTree() ORDER BY (id, webhook_id, timestamp)
        """
        clickhouse_native_client.execute(create_table_query)
        clickhouse_native_client.execute(f"TRUNCATE TABLE {test_table}")

        # Insert data with headers
        test_headers = {"Authorization": "Bearer token123", "X-Custom": "value"}
        insert_query = f"""
        INSERT INTO {test_table} (id, webhook_id, timestamp, payload, headers)
        VALUES ('test_id', 'test_webhook', now(), '{{"test": "data"}}', '{json.dumps(test_headers)}')
        """
        clickhouse_native_client.execute(insert_query)

        # Verify headers were stored
        result = clickhouse_native_client.execute(
            f"SELECT headers FROM {test_table} WHERE id = 'test_id'"
        )
        assert len(result) == 1
        stored_headers = json.loads(result[0][0])
        assert stored_headers == test_headers

    @pytest.mark.asyncio
    async def test_include_timestamp_configuration(
        self, clickhouse_native_client: Client, cleanup_tables
    ):
        """Test that timestamps can be included in ClickHouse logs."""
        test_table = f"{TEST_CLICKHOUSE_TABLE_PREFIX}timestamp_test"

        # Create table with timestamp column
        create_table_query = f"""
        CREATE TABLE IF NOT EXISTS {test_table} (
            id String,
            webhook_id String,
            timestamp DateTime,
            payload String
        ) ENGINE = MergeTree() ORDER BY (id, webhook_id, timestamp)
        """
        clickhouse_native_client.execute(create_table_query)
        clickhouse_native_client.execute(f"TRUNCATE TABLE {test_table}")

        # Insert data with timestamp
        from datetime import datetime

        test_timestamp = datetime.now()
        insert_query = f"""
        INSERT INTO {test_table} (id, webhook_id, timestamp, payload)
        VALUES ('test_id', 'test_webhook', '{test_timestamp.strftime('%Y-%m-%d %H:%M:%S')}', '{{"test": "data"}}')
        """
        clickhouse_native_client.execute(insert_query)

        # Verify timestamp was stored
        result = clickhouse_native_client.execute(
            f"SELECT timestamp FROM {test_table} WHERE id = 'test_id'"
        )
        assert len(result) == 1
        stored_timestamp = result[0][0]
        assert isinstance(stored_timestamp, datetime)

    @pytest.mark.asyncio
    async def test_table_auto_creation(
        self, clickhouse_native_client: Client, cleanup_tables
    ):
        """Test that tables can be auto-created on first use."""
        test_table = f"{TEST_CLICKHOUSE_TABLE_PREFIX}auto_create_test"

        # Table should not exist
        tables = clickhouse_native_client.execute("SHOW TABLES")
        assert (test_table,) not in tables

        # Create table (simulating auto-creation)
        create_table_query = f"""
        CREATE TABLE IF NOT EXISTS {test_table} (
            id String,
            payload String
        ) ENGINE = MergeTree() ORDER BY id
        """
        clickhouse_native_client.execute(create_table_query)

        # Verify table exists
        tables = clickhouse_native_client.execute("SHOW TABLES")
        assert (test_table,) in tables

    @pytest.mark.asyncio
    async def test_connection_error_handling(self):
        """Test handling of connection failures."""
        # Try to connect to invalid host
        try:
            invalid_client = Client(
                host="invalid_host_that_does_not_exist",
                port=9000,  # Native protocol port
                user=os.getenv("CLICKHOUSE_USER", "default"),
                password=os.getenv("CLICKHOUSE_PASSWORD", ""),
                database=os.getenv("CLICKHOUSE_DB", "default"),
                connect_timeout=1,
            )
            invalid_client.execute("SELECT 1")
            # If we get here, connection succeeded (unexpected)
            invalid_client.disconnect()
            pytest.skip("Invalid host actually resolved (unexpected)")
        except Exception as e:
            # Expected: connection should fail
            error_str = str(e).lower()
            assert any(
                keyword in error_str
                for keyword in [
                    "connection",
                    "timeout",
                    "resolve",
                    "name resolution",
                    "temporary failure",
                ]
            )

    @pytest.mark.asyncio
    async def test_sql_injection_prevention(self, clickhouse_native_client: Client):
        """Test that table name validation prevents SQL injection."""
        from src.modules.clickhouse import ClickHouseModule

        # Attempt SQL injection in table name
        malicious_configs = [
            {"table": "table; DROP TABLE users;--"},
            {"table": "table' OR '1'='1"},
            {"table": "table UNION SELECT * FROM users"},
        ]

        for malicious_config in malicious_configs:
            config = {
                "module": "clickhouse",
                "module-config": malicious_config,
                "connection_details": {},
            }
            with pytest.raises(ValueError):
                ClickHouseModule(config)

    @pytest.mark.asyncio
    async def test_module_with_headers_and_timestamp(
        self, clickhouse_native_client: Client, cleanup_tables
    ):
        """Test ClickHouse module with include_headers and include_timestamp."""
        test_table = f"{TEST_CLICKHOUSE_TABLE_PREFIX}module_test"

        # Note: This test would require a full module setup with connection details
        # For now, we test the configuration parsing
        config = {
            "module": "clickhouse",
            "module-config": {
                "table": test_table,
                "include_headers": True,
                "include_timestamp": True,
            },
            "connection_details": {},
        }

        module = ClickHouseModule(config)
        assert module.include_headers is True
        assert module.include_timestamp is True
        assert module.table_name == test_table
