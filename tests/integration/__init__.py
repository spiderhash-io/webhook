"""
Integration tests for Core Webhook Module.

These tests run against real services (Redis, RabbitMQ, ClickHouse) and make
actual HTTP calls to a running FastAPI server. They are separate from unit
tests which use mocks and in-process testing.
"""
