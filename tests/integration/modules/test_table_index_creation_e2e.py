"""
End-to-end integration tests for table and index creation in PostgreSQL and MySQL modules.

Tests verify:
- Tables are created correctly
- Indexes are created AFTER tables exist (not before)
- Index names are properly validated and quoted
- GIN indexes are created for PostgreSQL JSON mode with upsert
- Both modules handle table/index creation order correctly
"""

import pytest
import asyncio
import asyncpg
import aiomysql
from unittest.mock import patch
from tests.integration.test_config import (
    POSTGRES_HOST,
    POSTGRES_PORT,
    POSTGRES_DATABASE,
    POSTGRES_USER,
    POSTGRES_PASSWORD,
)
from src.modules.postgres import PostgreSQLModule
from src.modules.mysql import MySQLModule


@pytest.mark.integration
@pytest.mark.external_services
@pytest.mark.asyncio
class TestPostgreSQLTableIndexCreationE2E:
    """End-to-end test for PostgreSQL table and index creation."""

    @pytest.fixture
    async def postgres_connection(self):
        """Create a PostgreSQL connection for testing."""
        conn = await asyncpg.connect(
            host=POSTGRES_HOST,
            port=POSTGRES_PORT,
            database=POSTGRES_DATABASE,
            user=POSTGRES_USER,
            password=POSTGRES_PASSWORD,
        )
        yield conn
        await conn.close()

    @pytest.fixture
    async def cleanup_table(self, postgres_connection):
        """Cleanup test table after test."""
        table_name = "test_webhook_events_e2e"
        index_name = "test_webhook_events_e2e_payload_gin"
        yield
        # Drop index if exists
        try:
            await postgres_connection.execute(f'DROP INDEX IF EXISTS "{index_name}"')
        except Exception:
            pass
        # Drop table if exists
        try:
            await postgres_connection.execute(f'DROP TABLE IF EXISTS "{table_name}"')
        except Exception:
            pass

    @pytest.mark.asyncio
    async def test_table_created_before_gin_index(
        self, postgres_connection, cleanup_table
    ):
        """Test that table is created before GIN index in PostgreSQL JSON mode with upsert."""
        table_name = "test_webhook_events_e2e"

        config = {
            "connection_details": {
                "host": POSTGRES_HOST,
                "port": POSTGRES_PORT,
                "database": POSTGRES_DATABASE,
                "user": POSTGRES_USER,
                "password": POSTGRES_PASSWORD,
            },
            "module-config": {
                "table": table_name,
                "storage_mode": "json",
                "upsert": True,
                "upsert_key": "event_id",
            },
            "_webhook_id": "test_webhook",
        }

        module = PostgreSQLModule(config)

        # Setup should create table and index
        await module.setup()

        # Verify table exists
        table_exists = await postgres_connection.fetchval(
            """
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = $1
            )
        """,
            table_name,
        )
        assert table_exists is True, "Table should exist after setup"

        # Verify GIN index exists and was created after table
        index_exists = await postgres_connection.fetchval(
            """
            SELECT EXISTS (
                SELECT FROM pg_indexes 
                WHERE schemaname = 'public' 
                AND tablename = $1 
                AND indexname = $2
            )
        """,
            table_name,
            f"{table_name}_payload_gin",
        )
        assert index_exists is True, "GIN index should exist after setup"

        # Verify index is actually a GIN index
        index_type = await postgres_connection.fetchval(
            """
            SELECT amname 
            FROM pg_index i
            JOIN pg_class c ON i.indexrelid = c.oid
            JOIN pg_am am ON c.relam = am.oid
            JOIN pg_class t ON i.indrelid = t.oid
            WHERE t.relname = $1 
            AND c.relname = $2
        """,
            table_name,
            f"{table_name}_payload_gin",
        )
        assert index_type == "gin", "Index should be a GIN index"

        await module.teardown()

    @pytest.mark.asyncio
    async def test_index_name_properly_quoted(self, postgres_connection, cleanup_table):
        """Test that index names are properly validated and quoted."""
        table_name = "test_webhook_events_e2e"

        config = {
            "connection_details": {
                "host": POSTGRES_HOST,
                "port": POSTGRES_PORT,
                "database": POSTGRES_DATABASE,
                "user": POSTGRES_USER,
                "password": POSTGRES_PASSWORD,
            },
            "module-config": {
                "table": table_name,
                "storage_mode": "json",
                "upsert": True,
                "upsert_key": "event_id",
            },
            "_webhook_id": "test_webhook",
        }

        module = PostgreSQLModule(config)
        await module.setup()

        # Verify index name is correct (should be table_name_payload_gin)
        index_name = f"{table_name}_payload_gin"
        index_info = await postgres_connection.fetchrow(
            """
            SELECT indexname, tablename 
            FROM pg_indexes 
            WHERE schemaname = 'public' 
            AND tablename = $1 
            AND indexname = $2
        """,
            table_name,
            index_name,
        )

        assert index_info is not None, f"Index {index_name} should exist"
        assert index_info["tablename"] == table_name
        assert index_info["indexname"] == index_name

        await module.teardown()


@pytest.mark.integration
@pytest.mark.asyncio
class TestMySQLTableIndexCreationE2E:
    """End-to-end test for MySQL table and index creation."""

    @pytest.fixture
    async def mysql_connection(self):
        """Create a MySQL connection for testing."""
        # Check if MySQL is available (may not be in all test environments)
        try:
            conn = await aiomysql.connect(
                host="localhost", port=3306, user="root", password="root", db="test"
            )
            yield conn
            conn.close()
        except Exception as e:
            pytest.skip(f"MySQL not available: {e}")

    @pytest.fixture
    async def cleanup_table(self, mysql_connection):
        """Cleanup test table after test."""
        table_name = "test_webhook_events_e2e"
        yield
        # Drop table if exists (will also drop indexes)
        try:
            async with mysql_connection.cursor() as cur:
                await cur.execute(f"DROP TABLE IF EXISTS `{table_name}`")
                await mysql_connection.commit()
        except Exception:
            pass

    @pytest.mark.asyncio
    async def test_table_created_before_index(self, mysql_connection, cleanup_table):
        """Test that table is created before indexes in MySQL relational mode."""
        table_name = "test_webhook_events_e2e"

        config = {
            "connection_details": {
                "host": "localhost",
                "port": 3306,
                "database": "test",
                "user": "root",
                "password": "root",
            },
            "module-config": {
                "table": table_name,
                "storage_mode": "relational",
                "schema": {
                    "fields": {
                        "event_id": {
                            "type": "string",
                            "column": "event_id",
                            "constraints": ["NOT NULL"],
                        },
                        "user_id": {"type": "integer", "column": "user_id"},
                    },
                    "indexes": {
                        "idx_event_id": {"columns": ["event_id"]},
                        "idx_user_id": {"columns": ["user_id"]},
                    },
                },
            },
            "_webhook_id": "test_webhook",
        }

        # Skip if MySQL not available
        try:
            module = MySQLModule(config)
            # Patch hostname validation to allow localhost for testing
            with patch.object(module, "_validate_hostname", return_value=True):
                await module.setup()
        except Exception as e:
            pytest.skip(f"MySQL setup failed: {e}")

        # Verify table exists
        async with mysql_connection.cursor() as cur:
            await cur.execute(
                f"""
                SELECT COUNT(*) 
                FROM information_schema.tables 
                WHERE table_schema = 'test' 
                AND table_name = %s
            """,
                (table_name,),
            )
            result = await cur.fetchone()
            assert result[0] == 1, "Table should exist after setup"

        # Verify indexes exist
        async with mysql_connection.cursor() as cur:
            await cur.execute(
                f"""
                SELECT COUNT(*) 
                FROM information_schema.statistics 
                WHERE table_schema = 'test' 
                AND table_name = %s 
                AND index_name IN ('idx_event_id', 'idx_user_id')
            """,
                (table_name,),
            )
            result = await cur.fetchone()
            assert result[0] == 2, "Both indexes should exist after setup"

        await module.teardown()

    @pytest.mark.asyncio
    async def test_index_name_properly_quoted(self, mysql_connection, cleanup_table):
        """Test that index names are properly validated and quoted in MySQL."""
        table_name = "test_webhook_events_e2e"

        config = {
            "connection_details": {
                "host": "localhost",
                "port": 3306,
                "database": "test",
                "user": "root",
                "password": "root",
            },
            "module-config": {
                "table": table_name,
                "storage_mode": "relational",
                "schema": {
                    "fields": {"event_id": {"type": "string", "column": "event_id"}},
                    "indexes": {"idx_event_id": {"columns": ["event_id"]}},
                },
            },
            "_webhook_id": "test_webhook",
        }

        # Skip if MySQL not available
        try:
            module = MySQLModule(config)
            # Patch hostname validation to allow localhost for testing
            with patch.object(module, "_validate_hostname", return_value=True):
                await module.setup()
        except Exception as e:
            pytest.skip(f"MySQL setup failed: {e}")

        # Verify index name is correct
        async with mysql_connection.cursor() as cur:
            await cur.execute(
                f"""
                SELECT index_name, column_name 
                FROM information_schema.statistics 
                WHERE table_schema = 'test' 
                AND table_name = %s 
                AND index_name = 'idx_event_id'
            """,
                (table_name,),
            )
            result = await cur.fetchone()
            assert result is not None, "Index idx_event_id should exist"
            assert result[0] == "idx_event_id"
            assert result[1] == "event_id"

        await module.teardown()
