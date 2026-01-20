"""
Test configuration for integration tests.

This module contains configuration specific to integration tests,
including connection strings, test webhook definitions, and service endpoints.
"""

import os

# Service endpoints (from docker-compose.yaml)
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6380"))
REDIS_URL = f"redis://{REDIS_HOST}:{REDIS_PORT}"

RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "localhost")
RABBITMQ_PORT = int(os.getenv("RABBITMQ_PORT", "5672"))
RABBITMQ_USER = os.getenv("RABBITMQ_USER", "guest")
RABBITMQ_PASS = os.getenv("RABBITMQ_PASS", "guest")

CLICKHOUSE_HOST = os.getenv("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.getenv("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_HTTP_URL = f"http://{CLICKHOUSE_HOST}:{CLICKHOUSE_PORT}"

KAFKA_HOST = os.getenv("KAFKA_HOST", "localhost")
KAFKA_PORT = int(os.getenv("KAFKA_PORT", "19092"))
KAFKA_BOOTSTRAP_SERVERS = f"{KAFKA_HOST}:{KAFKA_PORT}"

MQTT_HOST = os.getenv("MQTT_HOST", "localhost")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
MQTT_TLS_PORT = int(os.getenv("MQTT_TLS_PORT", "8883"))
MQTT_USER = os.getenv("MQTT_USER", "")
MQTT_PASS = os.getenv("MQTT_PASS", "")

POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")
POSTGRES_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
POSTGRES_DATABASE = os.getenv("POSTGRES_DATABASE", "dapp")
POSTGRES_USER = os.getenv("POSTGRES_USER", "postgres")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "postgres")
POSTGRES_URL = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DATABASE}"

# FastAPI server endpoint
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")

# Test webhook configuration
TEST_WEBHOOK_ID = "integration_test_webhook"
TEST_AUTH_TOKEN = "test_integration_token_12345"

# Test data cleanup keys
TEST_REDIS_PREFIX = "test:integration:"
TEST_RABBITMQ_QUEUE_PREFIX = "test_integration_"
TEST_CLICKHOUSE_TABLE_PREFIX = "test_integration_"
TEST_KAFKA_TOPIC_PREFIX = "test_integration_"
TEST_MQTT_TOPIC_PREFIX = "test/integration/"
