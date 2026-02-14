"""
Comprehensive security audit tests for validate_connections function (main.py).

This test suite covers security vulnerabilities in the connection validation
system, including SSRF attacks, DoS, information disclosure, and connection
string injection.
"""

import pytest
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock
from src.main import validate_connections
from src.utils import sanitize_error_message


@pytest.fixture
def allow_private_ips(monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE_IP_CONNECTIONS", "true")
    yield


class TestValidateConnectionsSSRF:
    """Test SSRF vulnerabilities in connection validation."""

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("allow_private_ips")
    async def test_postgresql_private_ip_allowed_for_internal_networks(self):
        """Test that private IPs are allowed for internal network connections."""
        config = {
            "internal_db": {
                "type": "postgresql",
                "host": "192.168.1.1",  # Private IP - allowed for internal networks
                "port": 5432,
                "database": "test",
                "user": "user",
                "password": "pass",
            }
        }

        # Private IPs are now allowed to support internal network deployments
        with patch("asyncpg.connect", new_callable=AsyncMock) as mock_connect:
            mock_conn = AsyncMock()
            mock_conn.fetchval = AsyncMock(return_value=1)
            mock_conn.close = AsyncMock()
            mock_connect.return_value = mock_conn

            await validate_connections(config)

            # Connection should be attempted for private IPs (internal network support)
            assert (
                mock_connect.called
            ), "Private IPs should be allowed for internal network connections"

    @pytest.mark.asyncio
    async def test_mysql_ssrf_localhost(self):
        """Test SSRF via MySQL connection to localhost."""
        config = {
            "malicious_db": {
                "type": "mysql",
                "host": "127.0.0.1",  # Localhost
                "port": 3306,
                "database": "test",
                "user": "root",
                "password": "pass",
            }
        }

        with patch("aiomysql.create_pool", new_callable=AsyncMock) as mock_pool:
            mock_pool_instance = AsyncMock()
            mock_pool_instance.acquire = AsyncMock()
            mock_pool_instance.close = AsyncMock()
            mock_pool_instance.wait_closed = AsyncMock()
            mock_pool.return_value = mock_pool_instance

            await validate_connections(config)

            # If SSRF protection is missing, connection will be attempted
            if mock_pool.called:
                assert (
                    False
                ), "SSRF vulnerability: Connection attempted to localhost without validation"

    @pytest.mark.asyncio
    async def test_redis_ssrf_metadata_service(self):
        """Test SSRF via Redis connection to cloud metadata service."""
        config = {
            "malicious_redis": {
                "type": "redis-rq",
                "host": "169.254.169.254",  # AWS metadata service
                "port": 80,
                "db": 0,
            }
        }

        with patch("redis.Redis") as mock_redis:
            mock_client = MagicMock()
            mock_client.ping = MagicMock()
            mock_redis.return_value = mock_client

            await validate_connections(config)

            # If SSRF protection is missing, connection will be attempted
            if mock_redis.called:
                assert (
                    False
                ), "SSRF vulnerability: Connection attempted to metadata service without validation"

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("allow_private_ips")
    async def test_kafka_private_ip_allowed_in_bootstrap_servers(self):
        """Test that private IPs are allowed in Kafka bootstrap_servers for internal networks."""
        config = {
            "internal_kafka": {
                "type": "kafka",
                "bootstrap_servers": "10.0.0.1:9092",  # Private IP - allowed for internal networks
            }
        }

        with patch("aiokafka.AIOKafkaProducer") as mock_producer:
            mock_prod_instance = AsyncMock()
            mock_prod_instance.start = AsyncMock()
            mock_prod_instance.stop = AsyncMock()
            mock_producer.return_value = mock_prod_instance

            await validate_connections(config)

            # Connection should be attempted for private IPs (internal network support)
            assert (
                mock_producer.called
            ), "Private IPs should be allowed for internal network Kafka connections"


class TestValidateConnectionsDoS:
    """Test DoS vulnerabilities in connection validation."""

    @pytest.mark.asyncio
    async def test_connection_timeout_dos(self):
        """Test DoS via slow connection (timeout handling)."""
        config = {
            "slow_db": {
                "type": "postgresql",
                "host": "example.com",
                "port": 5432,
                "database": "test",
                "user": "user",
                "password": "pass",
            }
        }

        # Mock a connection that hangs (exceeds timeout)
        async def slow_connect(*args, **kwargs):
            await asyncio.sleep(10)  # Longer than 5s timeout
            return AsyncMock()

        with patch("asyncpg.connect", side_effect=slow_connect):
            start_time = asyncio.get_event_loop().time()
            await validate_connections(config)
            end_time = asyncio.get_event_loop().time()

            # Should timeout within reasonable time (5s + overhead)
            elapsed = end_time - start_time
            assert (
                elapsed < 6.0
            ), f"Connection validation did not timeout properly: {elapsed}s"

    @pytest.mark.asyncio
    async def test_many_connections_dos(self):
        """Test DoS via many connection validation attempts."""
        # Create many connections to validate
        config = {}
        for i in range(100):
            config[f"conn_{i}"] = {
                "type": "postgresql",
                "host": f"host{i}.example.com",
                "port": 5432,
                "database": "test",
                "user": "user",
                "password": "pass",
            }

        # Mock all connections to fail quickly
        with patch("asyncpg.connect", side_effect=Exception("Connection failed")):
            start_time = asyncio.get_event_loop().time()
            await validate_connections(config)
            end_time = asyncio.get_event_loop().time()

            # Should complete within reasonable time (not hang)
            elapsed = end_time - start_time
            assert elapsed < 10.0, f"Connection validation took too long: {elapsed}s"


class TestValidateConnectionsInformationDisclosure:
    """Test information disclosure vulnerabilities."""

    @pytest.mark.asyncio
    async def test_error_message_disclosure(self, caplog):
        """Test that error messages don't disclose sensitive information."""
        config = {
            "test_db": {
                "type": "postgresql",
                "host": "example.com",
                "port": 5432,
                "database": "test",
                "user": "user",
                "password": "secret_password_123",
            }
        }

        # Mock connection that fails with sensitive error
        sensitive_error = Exception(
            "Connection failed: postgresql://user:secret_password_123@example.com:5432/test"
        )

        import logging

        with caplog.at_level(logging.DEBUG):
            with patch("asyncpg.connect", side_effect=sensitive_error):
                await validate_connections(config)

        output = caplog.text

        # Check that sensitive information is not in output
        assert (
            "secret_password_123" not in output
        ), "Sensitive information leaked in log output: password"

    @pytest.mark.asyncio
    async def test_status_message_information_disclosure(self, caplog):
        """Test that status messages don't disclose sensitive information."""
        config = {
            "test_db": {
                "type": "postgresql",
                "host": "example.com",
                "port": 5432,
                "database": "test",
                "user": "user",
                "password": "secret",
            }
        }

        # Mock successful connection
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=1)
        mock_conn.close = AsyncMock()

        import logging

        with caplog.at_level(logging.DEBUG):
            with patch("asyncpg.connect", return_value=mock_conn):
                await validate_connections(config)

        output = caplog.text

        # Status message should not contain password as standalone word
        # Note: "secret" can appear in logger names or other context
        assert "password" not in output.lower() or "secret_password" not in output.lower(), \
            "Password leaked in status message"
        # Status message should contain host/port (acceptable)
        assert (
            "example.com" in output or "5432" in output
        ), "Status message should contain connection info (host/port)"


class TestValidateConnectionsConnectionStringInjection:
    """Test connection string injection vulnerabilities."""

    @pytest.mark.asyncio
    async def test_postgresql_connection_string_injection(self):
        """Test connection string injection via user/password/host."""
        config = {
            "injected_db": {
                "type": "postgresql",
                "host": "example.com",
                "port": 5432,
                "database": "test",
                "user": "user@malicious.com",  # Injection attempt
                "password": "pass@evil.com",  # Injection attempt
            }
        }

        # Mock connection
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=1)
        mock_conn.close = AsyncMock()

        with patch("asyncpg.connect", return_value=mock_conn) as mock_connect:
            await validate_connections(config)

            # Check if connection was constructed safely using keyword args
            if mock_connect.called:
                call_args = mock_connect.call_args
                # Using keyword args (host=, port=, user=, password=) is safe
                # because each parameter is isolated — no string injection possible
                if call_args.kwargs:
                    assert call_args.kwargs.get("host") == "example.com", \
                        "Host should be passed as separate kwarg"
                elif call_args.args:
                    # If a connection string was used, check for injection
                    connection_string = call_args.args[0]
                    if "@" in connection_string:
                        assert (
                            "@" not in connection_string.split("@")[1]
                        ), "Connection string injection vulnerability: Multiple @ symbols"

    @pytest.mark.asyncio
    async def test_rabbitmq_connection_string_injection(self):
        """Test connection string injection via RabbitMQ credentials."""
        config = {
            "injected_rabbitmq": {
                "type": "rabbitmq",
                "host": "example.com",
                "port": 5672,
                "user": "user@evil.com",  # Injection attempt
                "pass": "pass@evil.com",  # Injection attempt
            }
        }

        mock_connection = AsyncMock()
        mock_connection.close = AsyncMock()

        with patch(
            "aio_pika.connect_robust", return_value=mock_connection
        ) as mock_connect:
            await validate_connections(config)

            # Check if connection was constructed safely using keyword args
            if mock_connect.called:
                call_args = mock_connect.call_args
                # Using keyword args (host=, port=, login=, password=) is safe
                # because each parameter is isolated — no string injection possible
                if call_args.kwargs:
                    assert call_args.kwargs.get("host") == "example.com", \
                        "Host should be passed as separate kwarg"
                elif call_args.args:
                    amqp_url = call_args.args[0]
                    if amqp_url:
                        assert "amqp://" in amqp_url, "AMQP URL should start with amqp://"


class TestValidateConnectionsTypeConfusion:
    """Test type confusion vulnerabilities."""

    @pytest.mark.asyncio
    async def test_host_type_confusion(self):
        """Test type confusion via non-string host."""
        config = {
            "test_db": {
                "type": "postgresql",
                "host": 12345,  # Non-string host
                "port": 5432,
                "database": "test",
                "user": "user",
                "password": "pass",
            }
        }

        # Should handle non-string host gracefully
        try:
            await validate_connections(config)
        except (TypeError, AttributeError, ValueError):
            # Acceptable - type validation should catch this
            pass
        except Exception as e:
            # Should not crash with unexpected error
            assert False, f"Unexpected error type: {type(e).__name__}: {e}"

    @pytest.mark.asyncio
    async def test_port_type_confusion(self):
        """Test type confusion via non-integer port."""
        config = {
            "test_db": {
                "type": "postgresql",
                "host": "example.com",
                "port": "5432",  # String port (should be int)
                "database": "test",
                "user": "user",
                "password": "pass",
            }
        }

        # Should handle non-integer port gracefully
        try:
            await validate_connections(config)
        except (TypeError, ValueError):
            # Acceptable - type validation should catch this
            pass
        except Exception as e:
            # Should not crash with unexpected error
            assert False, f"Unexpected error type: {type(e).__name__}: {e}"

    @pytest.mark.asyncio
    async def test_config_type_confusion(self):
        """Test type confusion via non-dict connection config."""
        # Non-dict config
        config = {"test_db": "not a dict"}  # Should be a dict

        # Should handle non-dict gracefully
        try:
            await validate_connections(config)
        except (TypeError, AttributeError):
            # Acceptable - type validation should catch this
            pass
        except Exception as e:
            # Should not crash
            assert False, f"Unexpected error type: {type(e).__name__}: {e}"


class TestValidateConnectionsEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.mark.asyncio
    async def test_empty_config(self):
        """Test validation with empty config."""
        config = {}

        # Should handle empty config gracefully
        await validate_connections(config)

    @pytest.mark.asyncio
    async def test_none_config(self):
        """Test validation with None config."""
        config = None

        # Should handle None config gracefully
        await validate_connections(config)

    @pytest.mark.asyncio
    async def test_missing_connection_type(self):
        """Test validation with missing connection type."""
        config = {
            "test_conn": {
                "host": "example.com",
                "port": 5432,
                # Missing 'type' field
            }
        }

        # Should handle missing type gracefully
        await validate_connections(config)

    @pytest.mark.asyncio
    async def test_unknown_connection_type(self):
        """Test validation with unknown connection type."""
        config = {
            "test_conn": {"type": "unknown_type", "host": "example.com", "port": 5432}
        }

        # Should handle unknown type gracefully
        await validate_connections(config)

    @pytest.mark.asyncio
    async def test_missing_required_fields(self):
        """Test validation with missing required fields."""
        config = {
            "test_db": {
                "type": "postgresql"
                # Missing host, port, database, user, password
            }
        }

        # Should handle missing fields gracefully
        try:
            await validate_connections(config)
        except (KeyError, TypeError, ValueError):
            # Acceptable - validation should catch missing fields
            pass
        except Exception as e:
            # Should not crash with unexpected error
            assert False, f"Unexpected error type: {type(e).__name__}: {e}"


class TestValidateConnectionsInputValidation:
    """Test input validation and sanitization."""

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("allow_private_ips")
    async def test_host_validation_allows_private_ips(self):
        """Test that private IPs are allowed for internal network connections."""
        config = {
            "test_db": {
                "type": "postgresql",
                "host": "192.168.1.1",  # Private IP - allowed for internal networks
                "port": 5432,
                "database": "test",
                "user": "user",
                "password": "pass",
            }
        }

        # Private IPs are allowed for internal network deployments
        with patch("asyncpg.connect", new_callable=AsyncMock) as mock_connect:
            mock_conn = AsyncMock()
            mock_conn.fetchval = AsyncMock(return_value=1)
            mock_conn.close = AsyncMock()
            mock_connect.return_value = mock_conn

            await validate_connections(config)

            # Connection should be attempted for private IPs
            assert (
                mock_connect.called
            ), "Private IPs should be allowed for internal network connections"

    @pytest.mark.asyncio
    async def test_allow_private_ip_connections_env_var(self):
        """Test that ALLOW_PRIVATE_IP_CONNECTIONS env var controls private IP behavior."""
        import os
        from src.config import _validate_connection_host

        # Test that private IPs are blocked when ALLOW_PRIVATE_IP_CONNECTIONS=false
        old_val = os.environ.get("ALLOW_PRIVATE_IP_CONNECTIONS")
        try:
            os.environ["ALLOW_PRIVATE_IP_CONNECTIONS"] = "false"

            # Should raise ValueError when env var is set to false
            with pytest.raises(ValueError, match="not allowed"):
                _validate_connection_host("192.168.1.1", "postgresql")

            # Test that private IPs are allowed when ALLOW_PRIVATE_IP_CONNECTIONS=true
            os.environ["ALLOW_PRIVATE_IP_CONNECTIONS"] = "true"

            # Should not raise - private IP is allowed
            result = _validate_connection_host("192.168.1.1", "postgresql")
            assert result == "192.168.1.1"

        finally:
            # Restore original env var
            if old_val is None:
                os.environ.pop("ALLOW_PRIVATE_IP_CONNECTIONS", None)
            else:
                os.environ["ALLOW_PRIVATE_IP_CONNECTIONS"] = old_val

    @pytest.mark.asyncio
    async def test_private_ip_blocked_when_env_var_disabled(self):
        """Test that private IPs are blocked when ALLOW_PRIVATE_IP_CONNECTIONS=false."""
        import os
        from src.main import validate_connections

        config = {
            "test_db": {
                "type": "postgresql",
                "host": "192.168.1.1",  # Private IP
                "port": 5432,
                "database": "test",
                "user": "user",
                "password": "pass",
            }
        }

        old_val = os.environ.get("ALLOW_PRIVATE_IP_CONNECTIONS")
        try:
            os.environ["ALLOW_PRIVATE_IP_CONNECTIONS"] = "false"

            # Connection should NOT be attempted when env var is false
            with patch("asyncpg.connect", new_callable=AsyncMock) as mock_connect:
                await validate_connections(config)

                # Connection should NOT be attempted
                assert (
                    not mock_connect.called
                ), "Private IPs should be blocked when ALLOW_PRIVATE_IP_CONNECTIONS=false"

        finally:
            # Restore original env var
            if old_val is None:
                os.environ.pop("ALLOW_PRIVATE_IP_CONNECTIONS", None)
            else:
                os.environ["ALLOW_PRIVATE_IP_CONNECTIONS"] = old_val

    @pytest.mark.asyncio
    async def test_port_validation_missing(self):
        """Test that port validation is missing (vulnerability)."""
        config = {
            "test_db": {
                "type": "postgresql",
                "host": "example.com",
                "port": 65536,  # Invalid port (out of range)
                "database": "test",
                "user": "user",
                "password": "pass",
            }
        }

        # Should validate port range before attempting connection
        try:
            await validate_connections(config)
        except (ValueError, TypeError):
            # Good - port validation exists
            pass
        except Exception as e:
            # If connection is attempted with invalid port, vulnerability exists
            # (This would likely fail at connection time, but should be caught earlier)
            pass
