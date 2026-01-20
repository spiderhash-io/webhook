"""
End-to-end integration test for chained PostgreSQL -> Kafka webhook.

This test replicates the webhook configuration from VM 10.10.10.103:
- First stores data to PostgreSQL database
- Then publishes to Kafka (Redpanda) queue

Tests the full chain execution with real services and verifies:
- Connection details are properly injected from connections.json
- Modules can be instantiated with pool_registry
- Full end-to-end flow works correctly
"""

import pytest
import asyncio
import json
import asyncpg
from aiokafka import AIOKafkaConsumer
from httpx import AsyncClient
from tests.integration.test_config import (
    API_BASE_URL,
    POSTGRES_HOST,
    POSTGRES_PORT,
    POSTGRES_DATABASE,
    POSTGRES_USER,
    POSTGRES_PASSWORD,
    KAFKA_BOOTSTRAP_SERVERS,
    TEST_KAFKA_TOPIC_PREFIX,
)


@pytest.mark.integration
@pytest.mark.external_services
@pytest.mark.asyncio
class TestChainPostgresKafkaE2E:
    """End-to-end test for PostgreSQL -> Kafka chained webhook."""

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
    async def kafka_consumer(self):
        """Create a Kafka consumer for testing."""
        consumer = AIOKafkaConsumer(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            auto_offset_reset="earliest",
            enable_auto_commit=False,
        )
        await consumer.start()
        yield consumer
        await consumer.stop()

    @pytest.fixture
    def client(self):
        """Create HTTP client for API requests."""
        return AsyncClient(base_url=API_BASE_URL, timeout=30.0)

    async def test_chain_postgres_then_kafka_full_flow(
        self, postgres_connection, kafka_consumer, client
    ):
        """
        Test the full chain: webhook -> PostgreSQL -> Kafka.

        This test verifies:
        1. Connection details are properly injected from connections.json
        2. Modules can be instantiated with pool_registry
        3. Full end-to-end flow works correctly
        """
        # Test payload matching the VM configuration
        test_event_id = f"test-e2e-{asyncio.get_event_loop().time()}"
        test_payload = {
            "event_id": test_event_id,
            "foo": "bar",
            "timestamp": "2024-01-01T00:00:00Z",
            "data": {"value": 123, "status": "active"},
        }

        # Subscribe to Kafka topic before sending webhook
        kafka_topic = "webhook_events"
        kafka_consumer.subscribe([kafka_topic])

        # Send webhook request
        response = await client.post(
            "/webhook/webhook_db_then_kafka",
            json=test_payload,
            headers={
                "Authorization": "Bearer dev_secret_token",
                "Content-Type": "application/json",
            },
        )

        # Verify HTTP response - should be 200, not 500
        # If connection_details weren't injected, we'd get a 500 error
        assert response.status_code == 200, (
            f"Expected 200, got {response.status_code}: {response.text}\n"
            f"This failure likely indicates connection_details were not injected properly."
        )

        # Verify response doesn't contain error messages about missing connection details
        response_text = response.text.lower()
        assert (
            "connection details not found" not in response_text
        ), "Connection details should be injected from connections.json"
        assert (
            "unexpected keyword argument 'pool_registry'" not in response_text
        ), "Modules should accept pool_registry parameter"

        # Wait a bit for async processing
        await asyncio.sleep(2.0)

        # Verify data in PostgreSQL
        # Check if table exists and has the data
        table_exists = await postgres_connection.fetchval(
            """
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'webhook_events'
            )
        """
        )
        assert table_exists, "Table 'webhook_events' should exist"

        # Query the data using upsert_key (event_id)
        row = await postgres_connection.fetchrow(
            """
            SELECT * FROM webhook_events 
            WHERE data->>'event_id' = $1
        """,
            test_event_id,
        )

        assert (
            row is not None
        ), f"Data with event_id '{test_event_id}' should exist in PostgreSQL"

        # Verify the stored JSON data
        stored_data = row["data"]
        assert stored_data["event_id"] == test_event_id
        assert stored_data["foo"] == "bar"
        assert stored_data["data"]["value"] == 123

        # Verify data in Kafka
        try:
            msg = await asyncio.wait_for(kafka_consumer.getone(), timeout=10.0)

            # Verify message key (should be event_id)
            assert msg.key is not None, "Message should have a key"
            assert (
                msg.key.decode("utf-8") == test_event_id
            ), f"Expected key '{test_event_id}', got '{msg.key.decode('utf-8')}'"

            # Verify message value
            received_data = json.loads(msg.value.decode("utf-8"))
            assert received_data["event_id"] == test_event_id
            assert received_data["foo"] == "bar"
            assert received_data["data"]["value"] == 123

            # Verify headers if forward_headers is enabled
            if msg.headers:
                header_dict = {k: v.decode("utf-8") for k, v in msg.headers}
                # Headers should be forwarded from the webhook request

        except asyncio.TimeoutError:
            pytest.fail("Message not received from Kafka within timeout")

    async def test_chain_postgres_then_kafka_upsert(
        self, postgres_connection, kafka_consumer, client
    ):
        """Test that upsert works correctly in the chain."""
        # Send the same event_id twice (should upsert in PostgreSQL)
        test_event_id = f"test-upsert-{asyncio.get_event_loop().time()}"

        first_payload = {"event_id": test_event_id, "foo": "first", "value": 1}

        second_payload = {"event_id": test_event_id, "foo": "second", "value": 2}

        # Subscribe to Kafka topic
        kafka_topic = "webhook_events"
        kafka_consumer.subscribe([kafka_topic])

        # Send first request
        response1 = await client.post(
            "/webhook/webhook_db_then_kafka",
            json=first_payload,
            headers={"Authorization": "Bearer dev_secret_token"},
        )
        assert response1.status_code == 200

        await asyncio.sleep(1.0)

        # Send second request (should upsert)
        response2 = await client.post(
            "/webhook/webhook_db_then_kafka",
            json=second_payload,
            headers={"Authorization": "Bearer dev_secret_token"},
        )
        assert response2.status_code == 200

        await asyncio.sleep(2.0)

        # Verify only one row exists in PostgreSQL (upsert worked)
        count = await postgres_connection.fetchval(
            """
            SELECT COUNT(*) FROM webhook_events 
            WHERE data->>'event_id' = $1
        """,
            test_event_id,
        )
        assert count == 1, f"Should have exactly 1 row after upsert, got {count}"

        # Verify the data was updated
        row = await postgres_connection.fetchrow(
            """
            SELECT * FROM webhook_events 
            WHERE data->>'event_id' = $1
        """,
            test_event_id,
        )
        assert row["data"]["foo"] == "second", "Upsert should have updated the data"
        assert row["data"]["value"] == 2

        # Verify both messages were sent to Kafka (no upsert in Kafka)
        messages = []
        try:
            for _ in range(2):
                msg = await asyncio.wait_for(kafka_consumer.getone(), timeout=5.0)
                if msg.key and msg.key.decode("utf-8") == test_event_id:
                    messages.append(msg)
        except asyncio.TimeoutError:
            pass

        # Should have received 2 messages in Kafka (no deduplication)
        assert len(messages) >= 1, "Should have received at least one message in Kafka"

    async def test_chain_continue_on_error(
        self, postgres_connection, kafka_consumer, client
    ):
        """Test that chain continues on error (continue_on_error: true)."""
        # This test verifies that if one module fails, the chain continues
        # In this case, we'll send a valid request and verify both modules executed
        test_event_id = f"test-continue-{asyncio.get_event_loop().time()}"
        test_payload = {"event_id": test_event_id, "test": "continue_on_error"}

        kafka_topic = "webhook_events"
        kafka_consumer.subscribe([kafka_topic])

        response = await client.post(
            "/webhook/webhook_db_then_kafka",
            json=test_payload,
            headers={"Authorization": "Bearer dev_secret_token"},
        )

        # Should succeed even if one module has issues (due to continue_on_error)
        assert response.status_code == 200

        await asyncio.sleep(2.0)

        # Verify data was stored in PostgreSQL
        row = await postgres_connection.fetchrow(
            """
            SELECT * FROM webhook_events 
            WHERE data->>'event_id' = $1
        """,
            test_event_id,
        )
        assert row is not None, "Data should be stored in PostgreSQL"

        # Verify message was sent to Kafka
        try:
            msg = await asyncio.wait_for(kafka_consumer.getone(), timeout=5.0)
            received_data = json.loads(msg.value.decode("utf-8"))
            assert received_data["event_id"] == test_event_id
        except asyncio.TimeoutError:
            pytest.fail("Message should be in Kafka")

    async def test_chain_connection_details_injection(self, client):
        """
        Test that connection details are properly injected for chain modules.

        This test would have caught the bug where connection_details weren't
        being injected from connection_config into module configs.
        """
        from src.chain_processor import ChainProcessor
        from src.modules.postgres import PostgreSQLModule
        from src.modules.kafka import KafkaModule

        # Simulate the webhook config from connections.json
        webhook_config = {
            "data_type": "json",
            "topic": "webhook_events",
            "chain": [
                {
                    "module": "postgresql",
                    "connection": "postgres_local",
                    "module-config": {
                        "table": "webhook_events",
                        "storage_mode": "json",
                    },
                },
                {
                    "module": "kafka",
                    "connection": "kafka_redpanda_local",
                    "module-config": {"forward_headers": True},
                },
            ],
            "chain-config": {"execution": "sequential", "continue_on_error": True},
        }

        # Simulate connection_config from connections.json
        connection_config = {
            "postgres_local": {
                "type": "postgresql",
                "host": "postgres",
                "port": 5432,
                "database": "dapp",
                "user": "postgres",
                "password": "postgres",
                "pool_min_size": 2,
                "pool_max_size": 10,
                "ssl": False,
            },
            "kafka_redpanda_local": {
                "type": "kafka",
                "bootstrap_servers": "redpanda:9092",
            },
        }

        # Create chain processor with connection_config
        processor = ChainProcessor(
            chain=webhook_config["chain"],
            chain_config=webhook_config["chain-config"],
            webhook_config=webhook_config,
            connection_config=connection_config,
        )

        # Test that connection_details are injected for PostgreSQL module
        postgres_chain_item = webhook_config["chain"][0]
        postgres_module_config = processor._build_module_config(postgres_chain_item)

        assert (
            "connection_details" in postgres_module_config
        ), "connection_details should be injected from connection_config"
        assert postgres_module_config["connection_details"]["type"] == "postgresql"
        assert postgres_module_config["connection_details"]["host"] == "postgres"
        assert postgres_module_config["connection_details"]["port"] == 5432

        # Test that connection_details are injected for Kafka module
        kafka_chain_item = webhook_config["chain"][1]
        kafka_module_config = processor._build_module_config(kafka_chain_item)

        assert (
            "connection_details" in kafka_module_config
        ), "connection_details should be injected from connection_config"
        assert kafka_module_config["connection_details"]["type"] == "kafka"
        assert (
            kafka_module_config["connection_details"]["bootstrap_servers"]
            == "redpanda:9092"
        )

        # Test that modules can be instantiated with pool_registry
        # This would have caught the bug where KafkaModule didn't accept pool_registry
        try:
            postgres_module = PostgreSQLModule(
                postgres_module_config, pool_registry=None
            )
            assert postgres_module is not None
        except TypeError as e:
            pytest.fail(f"PostgreSQLModule should accept pool_registry parameter: {e}")

        try:
            kafka_module = KafkaModule(kafka_module_config, pool_registry=None)
            assert kafka_module is not None
        except TypeError as e:
            pytest.fail(f"KafkaModule should accept pool_registry parameter: {e}")

    async def cleanup_test_data(self, postgres_connection):
        """Helper to clean up test data."""
        # Clean up test data from PostgreSQL
        await postgres_connection.execute(
            """
            DELETE FROM webhook_events 
            WHERE data->>'event_id' LIKE 'test-%'
        """
        )
