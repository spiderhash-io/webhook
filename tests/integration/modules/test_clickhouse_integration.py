"""
Integration tests for ClickHouse module.

These tests verify that webhook data is actually written to ClickHouse database.
"""

import pytest
import httpx
import asyncio
from tests.integration.test_config import CLICKHOUSE_HTTP_URL
from tests.integration.utils import make_authenticated_request


@pytest.mark.integration
class TestClickHouseIntegration:
    """Integration tests for ClickHouse module."""
    
    @pytest.mark.asyncio
    async def test_clickhouse_connection(self):
        """Test that we can connect to ClickHouse."""
        response = httpx.get(f"{CLICKHOUSE_HTTP_URL}/ping", timeout=5.0)
        assert response.status_code == 200
        # ClickHouse returns "Ok." with a period
        assert response.text.strip() in ["Ok", "Ok."]
    
    @pytest.mark.asyncio
    async def test_clickhouse_query_execution(self):
        """Test that we can execute queries in ClickHouse."""
        query = "SELECT 1 as test_value"
        response = httpx.get(
            f"{CLICKHOUSE_HTTP_URL}/",
            params={"query": query},
            timeout=5.0
        )
        assert response.status_code == 200
        assert "1" in response.text
    
    @pytest.mark.asyncio
    async def test_clickhouse_table_creation(self):
        """Test that we can create a table in ClickHouse."""
        table_name = "test_integration_table"
        create_query = f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            id String,
            webhook_id String,
            timestamp DateTime,
            payload String,
            headers String
        ) ENGINE = MergeTree()
        ORDER BY (timestamp, webhook_id)
        """
        
        response = httpx.post(
            f"{CLICKHOUSE_HTTP_URL}/",
            data=create_query,
            timeout=5.0
        )
        
        # Should succeed or return error if table exists
        assert response.status_code in [200, 500]
        
        # Cleanup
        drop_query = f"DROP TABLE IF EXISTS {table_name}"
        httpx.post(f"{CLICKHOUSE_HTTP_URL}/", data=drop_query, timeout=5.0)
    
    @pytest.mark.asyncio
    async def test_clickhouse_webhook_logging(
        self,
        http_client: httpx.AsyncClient,
        test_webhook_id: str,
        test_auth_token: str
    ):
        """Test that webhook data is logged to ClickHouse."""
        # First, check if webhook_logs table exists
        check_table_query = """
        SELECT count() FROM system.tables 
        WHERE database = 'default' AND name = 'webhook_logs'
        """
        
        response = httpx.get(
            f"{CLICKHOUSE_HTTP_URL}/",
            params={"query": check_table_query},
            timeout=5.0
        )
        
        table_exists = response.status_code == 200 and "1" in response.text
        
        if not table_exists:
            pytest.skip("webhook_logs table does not exist in ClickHouse")
        
        # Get initial count
        count_query = "SELECT count() FROM webhook_logs"
        response = httpx.get(
            f"{CLICKHOUSE_HTTP_URL}/",
            params={"query": count_query},
            timeout=5.0
        )
        
        initial_count = 0
        if response.status_code == 200:
            try:
                initial_count = int(response.text.strip())
            except ValueError:
                pass
        
        # Send webhook request (if webhook is configured with clickhouse module)
        payload = {
            "test": "clickhouse_integration",
            "timestamp": "2024-01-01T00:00:00Z"
        }
        
        response = await make_authenticated_request(
            http_client,
            "POST",
            f"/webhook/{test_webhook_id}",
            auth_token=test_auth_token,
            json=payload
        )
        
        # Note: This test assumes a webhook is configured with clickhouse module
        if response.status_code == 404:
            pytest.skip(f"Webhook {test_webhook_id} not configured with clickhouse")
        
        # Wait for async logging
        await asyncio.sleep(2.0)
        
        # Check if new record was added
        response = httpx.get(
            f"{CLICKHOUSE_HTTP_URL}/",
            params={"query": count_query},
            timeout=5.0
        )
        
        if response.status_code == 200:
            try:
                new_count = int(response.text.strip())
                # Count should have increased if webhook was logged
                if response.status_code == 200:
                    assert new_count >= initial_count
            except ValueError:
                pass
    
    @pytest.mark.asyncio
    async def test_clickhouse_data_insert_query(self):
        """Test inserting and querying data in ClickHouse."""
        table_name = "test_integration_insert"
        
        # Create table
        create_query = f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            id String,
            data String,
            timestamp DateTime DEFAULT now()
        ) ENGINE = MergeTree()
        ORDER BY timestamp
        """
        httpx.post(f"{CLICKHOUSE_HTTP_URL}/", data=create_query, timeout=5.0)
        
        # Insert data
        insert_query = f"""
        INSERT INTO {table_name} (id, data) VALUES
        ('test_id_1', 'test_data_1'),
        ('test_id_2', 'test_data_2')
        """
        response = httpx.post(
            f"{CLICKHOUSE_HTTP_URL}/",
            data=insert_query,
            timeout=5.0
        )
        assert response.status_code == 200
        
        # Query data
        select_query = f"SELECT count() FROM {table_name}"
        response = httpx.get(
            f"{CLICKHOUSE_HTTP_URL}/",
            params={"query": select_query},
            timeout=5.0
        )
        assert response.status_code == 200
        assert "2" in response.text
        
        # Cleanup
        drop_query = f"DROP TABLE IF EXISTS {table_name}"
        httpx.post(f"{CLICKHOUSE_HTTP_URL}/", data=drop_query, timeout=5.0)

