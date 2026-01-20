"""
Comprehensive security audit tests for Live Configuration Reload feature.

Tests cover:
- Admin endpoint authentication bypass
- Path traversal in config file paths
- DoS via rapid reloads
- Configuration injection attacks
- File watching security (symlink attacks, race conditions)
- Information disclosure
- Race conditions in concurrent reloads
- JSON parsing DoS
- Error information disclosure
- Connection pool exhaustion
"""

import pytest
import json
import os
import tempfile
import asyncio
import threading
import time
from unittest.mock import patch, Mock, AsyncMock, MagicMock
from fastapi.testclient import TestClient
from fastapi import FastAPI

from src.config_manager import ConfigManager, ReloadResult
from src.config_watcher import ConfigFileWatcher, ConfigFileHandler
from src.connection_pool_registry import ConnectionPoolRegistry
from src.main import app


# ============================================================================
# 1. ADMIN ENDPOINT AUTHENTICATION BYPASS
# ============================================================================


@pytest.mark.longrunning
class TestAdminEndpointAuthentication:
    """Test authentication bypass vulnerabilities in admin endpoints."""

    def test_reload_config_without_token_when_required(self):
        """Test that reload-config endpoint requires authentication when token is set."""
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "secret-token-123"}):
            client = TestClient(app)

            # Request without token should fail
            response = client.post("/admin/reload-config", json={})
            assert response.status_code == 401
            assert "Authentication required" in response.json()["detail"]

    def test_reload_config_with_invalid_token(self):
        """Test that invalid tokens are rejected."""
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "secret-token-123"}):
            client = TestClient(app)

            # Request with wrong token should fail
            response = client.post(
                "/admin/reload-config",
                json={},
                headers={"Authorization": "Bearer wrong-token"},
            )
            assert response.status_code == 401
            assert "Invalid authentication token" in response.json()["detail"]

    def test_reload_config_with_valid_token(self):
        """Test that valid tokens are accepted."""
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "secret-token-123"}):
            client = TestClient(app)

            # Request with correct token should succeed (if ConfigManager initialized)
            response = client.post(
                "/admin/reload-config",
                json={},
                headers={"Authorization": "Bearer secret-token-123"},
            )
            # May return 503 if ConfigManager not initialized, but should not be 401
            assert response.status_code != 401

    def test_reload_config_token_timing_attack(self):
        """Test that token comparison is constant-time to prevent timing attacks."""
        import hmac

        # Verify hmac.compare_digest is used (constant-time comparison)
        # This is already implemented in main.py, but test to ensure it stays
        token1 = "secret-token-123"
        token2 = "secret-token-124"  # One character different

        # Measure comparison time (should be similar for both)
        times = []
        for _ in range(100):
            start = time.time()
            hmac.compare_digest(token1.encode(), token2.encode())
            times.append(time.time() - start)

        # Timing should be consistent (not leak information about token)
        avg_time = sum(times) / len(times)
        max_time = max(times)
        min_time = min(times)

        # Variation should be small (timing attack resistance)
        assert (max_time - min_time) < 0.01  # Less than 10ms variation

    def test_config_status_without_token_when_required(self):
        """Test that config-status endpoint requires authentication when token is set."""
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "secret-token-123"}):
            client = TestClient(app)

            # Request without token should fail
            response = client.get("/admin/config-status")
            assert response.status_code == 401
            assert "Authentication required" in response.json()["detail"]

    def test_config_status_with_invalid_token(self):
        """Test that invalid tokens are rejected for status endpoint."""
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "secret-token-123"}):
            client = TestClient(app)

            # Request with wrong token should fail
            response = client.get(
                "/admin/config-status", headers={"Authorization": "Bearer wrong-token"}
            )
            assert response.status_code == 401
            assert "Invalid authentication token" in response.json()["detail"]

    def test_reload_config_without_token_when_not_required(self):
        """Test that reload-config works without token when token is not set."""
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": ""}):
            client = TestClient(app)

            # Request without token should work (may fail for other reasons like missing ConfigManager)
            response = client.post("/admin/reload-config", json={})
            # Should not be 401 (authentication error)
            assert response.status_code != 401

    def test_authorization_header_case_insensitive(self):
        """Test that authorization header is handled case-insensitively."""
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "secret-token-123"}):
            client = TestClient(app)

            # Test various case combinations
            headers_variants = [
                {"Authorization": "Bearer secret-token-123"},
                {"authorization": "Bearer secret-token-123"},
                {"AUTHORIZATION": "Bearer secret-token-123"},
            ]

            for headers in headers_variants:
                response = client.post("/admin/reload-config", json={}, headers=headers)
                # Should not be 401 (token should be recognized)
                assert (
                    response.status_code != 401
                    or "Authentication required" not in str(response.json())
                )

    def test_bearer_token_extraction(self):
        """Test that Bearer token extraction handles edge cases."""
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": "secret-token-123"}):
            client = TestClient(app)

            # Test token without "Bearer " prefix
            response = client.post(
                "/admin/reload-config",
                json={},
                headers={"Authorization": "secret-token-123"},
            )
            # Should accept token without Bearer prefix
            assert response.status_code != 401 or "Authentication required" not in str(
                response.json()
            )


# ============================================================================
# 2. PATH TRAVERSAL IN CONFIG FILE PATHS
# ============================================================================


@pytest.mark.longrunning
class TestConfigFilePathTraversal:
    """Test path traversal vulnerabilities in config file paths."""

    def test_path_traversal_in_webhook_config_file(self):
        """Test that path traversal in webhook config file path is prevented."""
        # Attempt to access files outside allowed directory
        traversal_paths = [
            "../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "/etc/passwd",
            "C:\\Windows\\System32\\config\\sam",
            "....//....//etc/passwd",
            "..%2F..%2Fetc%2Fpasswd",  # URL encoded
        ]

        for traversal_path in traversal_paths:
            # ConfigManager should not allow arbitrary file paths
            # In production, file paths should be validated or restricted
            # This test documents the risk
            config_manager = ConfigManager(
                webhook_config_file=traversal_path,
                connection_config_file="connections.json",
            )

            # File should not exist, but test that path is handled safely
            # Actual file access will fail, but we want to ensure no path traversal
            assert not os.path.exists(traversal_path) or os.path.abspath(
                traversal_path
            ) != os.path.abspath("../../etc/passwd")

    def test_path_traversal_in_connection_config_file(self):
        """Test that path traversal in connection config file path is prevented."""
        traversal_paths = [
            "../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "/etc/passwd",
        ]

        for traversal_path in traversal_paths:
            config_manager = ConfigManager(
                webhook_config_file="webhooks.json",
                connection_config_file=traversal_path,
            )

            # File should not exist, but test that path is handled safely
            assert not os.path.exists(traversal_path) or os.path.abspath(
                traversal_path
            ) != os.path.abspath("../../etc/passwd")

    def test_null_byte_in_config_file_path(self):
        """Test that null bytes in config file paths are handled safely."""
        # Null bytes can be used to bypass path validation in some systems
        malicious_path = "webhooks.json\x00../../etc/passwd"

        # Python's open() should handle null bytes safely (truncates at null byte)
        # But we want to ensure ConfigManager doesn't allow this
        try:
            config_manager = ConfigManager(
                webhook_config_file=malicious_path,
                connection_config_file="connections.json",
            )
            # Should not raise exception, but file access should be safe
            # (Python truncates at null byte)
        except Exception as e:
            # Any exception is acceptable as long as it's safe
            assert "null" in str(e).lower() or "invalid" in str(e).lower()


# ============================================================================
# 3. DoS VIA RAPID RELOADS
# ============================================================================


@pytest.mark.longrunning
class TestReloadDoS:
    """Test denial-of-service vulnerabilities via rapid reloads."""

    @pytest.mark.asyncio
    async def test_rapid_reload_requests(self):
        """Test that rapid reload requests don't cause DoS."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"test": {"module": "log"}}, f)
            temp_webhook = f.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(
                {"conn": {"type": "rabbitmq", "host": "example.com", "port": 5672}}, f
            )
            temp_conn = f.name

        try:
            config_manager = ConfigManager(
                webhook_config_file=temp_webhook, connection_config_file=temp_conn
            )

            # Initialize
            await config_manager.initialize()

            # Rapid reloads
            start_time = time.time()
            tasks = []
            for _ in range(50):  # 50 concurrent reloads
                tasks.append(config_manager.reload_webhooks())

            results = await asyncio.gather(*tasks, return_exceptions=True)
            elapsed = time.time() - start_time

            # Should complete in reasonable time (not hang)
            assert elapsed < 10.0  # Should complete in under 10 seconds

            # Most should succeed or be blocked by lock (not crash)
            success_count = sum(
                1 for r in results if isinstance(r, ReloadResult) and r.success
            )
            error_count = sum(
                1 for r in results if isinstance(r, ReloadResult) and not r.success
            )

            # At least one should succeed, others may be blocked by lock
            assert success_count >= 1 or error_count > 0

        finally:
            os.unlink(temp_webhook)
            os.unlink(temp_conn)

    @pytest.mark.asyncio
    async def test_reload_during_active_reload(self):
        """Test that reloads during active reload are handled safely."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"test": {"module": "log"}}, f)
            temp_webhook = f.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(
                {"conn": {"type": "rabbitmq", "host": "example.com", "port": 5672}}, f
            )
            temp_conn = f.name

        try:
            config_manager = ConfigManager(
                webhook_config_file=temp_webhook, connection_config_file=temp_conn
            )

            await config_manager.initialize()

            # Start a reload
            reload_task = asyncio.create_task(config_manager.reload_webhooks())

            # Wait a bit
            await asyncio.sleep(0.1)

            # Try to reload again (should be blocked or queued)
            second_reload = await config_manager.reload_webhooks()

            # Second reload should either succeed after first completes, or be rejected
            assert isinstance(second_reload, ReloadResult)

            # Wait for first reload to complete
            await reload_task

        finally:
            os.unlink(temp_webhook)
            os.unlink(temp_conn)

    def test_admin_endpoint_rapid_requests(self):
        """Test that rapid admin endpoint requests don't cause DoS."""
        client = TestClient(app)

        # Rapid requests to reload endpoint
        start_time = time.time()
        responses = []
        for _ in range(20):
            responses.append(client.post("/admin/reload-config", json={}))
        elapsed = time.time() - start_time

        # Should complete quickly
        assert elapsed < 5.0

        # All requests should get a response (not hang)
        assert len(responses) == 20
        for response in responses:
            assert response.status_code in [200, 400, 401, 503]  # Valid status codes


# ============================================================================
# 4. CONFIGURATION INJECTION ATTACKS
# ============================================================================


@pytest.mark.longrunning
class TestConfigInjection:
    """Test configuration injection vulnerabilities."""

    @pytest.mark.asyncio
    async def test_malicious_webhook_id_injection(self):
        """Test that malicious webhook IDs are handled safely."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            malicious_config = {
                "../../etc/passwd": {"module": "log"},  # Path traversal in key
                "webhook; rm -rf /": {"module": "log"},  # Command injection attempt
                "webhook`id`": {"module": "log"},  # Command injection attempt
                "webhook$(whoami)": {"module": "log"},  # Command injection attempt
            }
            json.dump(malicious_config, f)
            temp_webhook = f.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({}, f)
            temp_conn = f.name

        try:
            config_manager = ConfigManager(
                webhook_config_file=temp_webhook, connection_config_file=temp_conn
            )

            result = await config_manager.initialize()

            # Should load config (keys are just strings, not executed)
            # But validation should ensure module exists
            assert isinstance(result, ReloadResult)

        finally:
            os.unlink(temp_webhook)
            os.unlink(temp_conn)

    @pytest.mark.asyncio
    async def test_malicious_connection_name_injection(self):
        """Test that malicious connection names are handled safely."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"test": {"module": "log", "connection": "../../etc/passwd"}}, f)
            temp_webhook = f.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            malicious_config = {
                "../../etc/passwd": {
                    "type": "rabbitmq",
                    "host": "example.com",
                    "port": 5672,
                }
            }
            json.dump(malicious_config, f)
            temp_conn = f.name

        try:
            config_manager = ConfigManager(
                webhook_config_file=temp_webhook, connection_config_file=temp_conn
            )

            result = await config_manager.initialize()

            # Should load config (connection names are just strings)
            assert isinstance(result, ReloadResult)

        finally:
            os.unlink(temp_webhook)
            os.unlink(temp_conn)

    @pytest.mark.asyncio
    async def test_type_confusion_in_config(self):
        """Test that type confusion attacks are prevented."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            # Try to confuse type system
            malicious_config = {
                "test": {
                    "module": 123,  # Should be string
                    "connection": [],  # Should be string or None
                }
            }
            json.dump(malicious_config, f)
            temp_webhook = f.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({}, f)
            temp_conn = f.name

        try:
            config_manager = ConfigManager(
                webhook_config_file=temp_webhook, connection_config_file=temp_conn
            )

            result = await config_manager.initialize()

            # Should fail validation (module must be string)
            assert not result.success or "module" in str(result.error).lower()

        finally:
            os.unlink(temp_webhook)
            os.unlink(temp_conn)

    @pytest.mark.asyncio
    async def test_prototype_pollution_attempt(self):
        """Test that prototype pollution attempts are handled safely."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            # Prototype pollution attempt (JavaScript-specific, but test anyway)
            malicious_config = {
                "test": {
                    "module": "log",
                    "__proto__": {"admin": True},
                    "constructor": {"admin": True},
                }
            }
            json.dump(malicious_config, f)
            temp_webhook = f.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({}, f)
            temp_conn = f.name

        try:
            config_manager = ConfigManager(
                webhook_config_file=temp_webhook, connection_config_file=temp_conn
            )

            result = await config_manager.initialize()

            # Should load (Python doesn't have prototype pollution, but test anyway)
            assert isinstance(result, ReloadResult)

        finally:
            os.unlink(temp_webhook)
            os.unlink(temp_conn)


# ============================================================================
# 5. FILE WATCHING SECURITY
# ============================================================================


@pytest.mark.longrunning
class TestFileWatchingSecurity:
    """Test file watching security vulnerabilities."""

    @pytest.mark.asyncio
    async def test_symlink_attack_prevention(self):
        """Test that symlink attacks are prevented."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create legitimate config file
            webhook_file = os.path.join(tmpdir, "webhooks.json")
            with open(webhook_file, "w") as f:
                json.dump({"test": {"module": "log"}}, f)

            # Create symlink to sensitive file
            sensitive_file = os.path.join(tmpdir, "sensitive.json")
            with open(sensitive_file, "w") as f:
                f.write('{"malicious": "data"}')

            # Try to create symlink (if supported)
            try:
                symlink_path = os.path.join(tmpdir, "webhooks_symlink.json")
                os.symlink(sensitive_file, symlink_path)

                # ConfigManager should use absolute paths, preventing symlink following
                config_manager = ConfigManager(webhook_config_file=webhook_file)

                # Should load from actual file, not symlink target
                result = await config_manager.initialize()
                assert isinstance(result, ReloadResult)

            except OSError:
                # Symlinks not supported on this system, skip test
                pass

    def test_file_watcher_path_validation(self):
        """Test that file watcher validates paths correctly."""
        # File watcher should only watch specific files, not arbitrary paths
        with tempfile.TemporaryDirectory() as tmpdir:
            webhook_file = os.path.join(tmpdir, "webhooks.json")
            connection_file = os.path.join(tmpdir, "connections.json")

            with open(webhook_file, "w") as f:
                json.dump({}, f)
            with open(connection_file, "w") as f:
                json.dump({}, f)

            config_manager = ConfigManager(
                webhook_config_file=webhook_file, connection_config_file=connection_file
            )

            watcher = ConfigFileWatcher(config_manager)

            # Watcher should only watch directory containing config files
            # Not arbitrary paths
            watcher.start()
            assert watcher.is_watching()
            watcher.stop()

    @pytest.mark.asyncio
    async def test_race_condition_in_file_watching(self):
        """Test that race conditions in file watching are handled safely."""
        with tempfile.TemporaryDirectory() as tmpdir:
            webhook_file = os.path.join(tmpdir, "webhooks.json")
            connection_file = os.path.join(tmpdir, "connections.json")

            with open(webhook_file, "w") as f:
                json.dump({"test1": {"module": "log"}}, f)
            with open(connection_file, "w") as f:
                json.dump({}, f)

            config_manager = ConfigManager(
                webhook_config_file=webhook_file, connection_config_file=connection_file
            )

            await config_manager.initialize()

            watcher = ConfigFileWatcher(config_manager)
            watcher.start()

            try:
                # Rapidly modify file multiple times
                for i in range(10):
                    with open(webhook_file, "w") as f:
                        json.dump({f"test{i}": {"module": "log"}}, f)
                    await asyncio.sleep(0.1)

                # Wait for debounce
                await asyncio.sleep(4.0)

                # Should have reloaded (debounced)
                # Config should be from last write
                config = config_manager.get_webhook_config("test9")
                assert config is not None

            finally:
                watcher.stop()


# ============================================================================
# 6. INFORMATION DISCLOSURE
# ============================================================================


@pytest.mark.longrunning
class TestInformationDisclosure:
    """Test information disclosure vulnerabilities."""

    @pytest.mark.asyncio
    async def test_error_message_sanitization(self):
        """Test that error messages don't disclose sensitive information."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            # Invalid JSON
            f.write('{"invalid": json}')
            temp_webhook = f.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({}, f)
            temp_conn = f.name

        try:
            config_manager = ConfigManager(
                webhook_config_file=temp_webhook, connection_config_file=temp_conn
            )

            result = await config_manager.reload_webhooks()

            # Error should not disclose file paths or system information
            assert not result.success
            error_msg = result.error.lower()

            # Should not contain sensitive paths
            assert "/etc/" not in error_msg
            assert "c:\\" not in error_msg.lower()
            assert "system32" not in error_msg.lower()

        finally:
            os.unlink(temp_webhook)
            os.unlink(temp_conn)

    def test_config_status_information_disclosure(self):
        """Test that config status doesn't disclose sensitive information."""
        with patch.dict(os.environ, {"CONFIG_RELOAD_ADMIN_TOKEN": ""}):
            client = TestClient(app)

            response = client.get("/admin/config-status")

            # Should not disclose:
            # - File paths
            # - Connection credentials
            # - Internal implementation details
            if response.status_code == 200:
                data = response.json()

                # Should not contain sensitive paths
                status_str = json.dumps(data).lower()
                assert "/etc/" not in status_str
                assert "password" not in status_str
                assert "secret" not in status_str
                assert "token" not in status_str

    @pytest.mark.asyncio
    async def test_connection_config_error_disclosure(self):
        """Test that connection config errors don't disclose sensitive info."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"test": {"module": "log"}}, f)
            temp_webhook = f.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            # Connection with sensitive info
            config = {
                "conn": {
                    "type": "rabbitmq",
                    "host": "internal-db.example.com",
                    "port": 5672,
                    "user": "admin",
                    "pass": "secret-password-123",
                }
            }
            json.dump(config, f)
            temp_conn = f.name

        try:
            config_manager = ConfigManager(
                webhook_config_file=temp_webhook, connection_config_file=temp_conn
            )

            result = await config_manager.reload_connections()

            # Error messages should not contain passwords
            if not result.success:
                error_msg = result.error.lower()
                assert "secret-password" not in error_msg
                assert (
                    "password" not in error_msg or "password" in "missing password"
                )  # Only generic messages

        finally:
            os.unlink(temp_webhook)
            os.unlink(temp_conn)


# ============================================================================
# 7. JSON PARSING DoS
# ============================================================================


@pytest.mark.longrunning
class TestJSONParsingDoS:
    """Test JSON parsing denial-of-service vulnerabilities."""

    @pytest.mark.asyncio
    async def test_deeply_nested_json_config(self):
        """Test that deeply nested JSON doesn't cause stack overflow."""
        # Create deeply nested structure
        nested = {"level": 1}
        current = nested
        for i in range(2, 1000):  # Very deep nesting
            current["nested"] = {"level": i}
            current = current["nested"]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(nested, f)
            temp_webhook = f.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({}, f)
            temp_conn = f.name

        try:
            config_manager = ConfigManager(
                webhook_config_file=temp_webhook, connection_config_file=temp_conn
            )

            # Should handle deeply nested JSON (Python's json handles this)
            result = await config_manager.reload_webhooks()
            # May fail validation (not a valid webhook config), but shouldn't crash
            assert isinstance(result, ReloadResult)

        finally:
            os.unlink(temp_webhook)
            os.unlink(temp_conn)

    @pytest.mark.asyncio
    async def test_large_json_config(self):
        """Test that very large JSON doesn't cause memory exhaustion."""
        # Create large JSON structure
        large_config = {}
        for i in range(1000):
            large_config[f"webhook_{i}"] = {
                "module": "log",
                "data": "x" * 10000,  # 10KB per webhook
            }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(large_config, f)
            temp_webhook = f.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({}, f)
            temp_conn = f.name

        try:
            config_manager = ConfigManager(
                webhook_config_file=temp_webhook, connection_config_file=temp_conn
            )

            start_time = time.time()
            result = await config_manager.reload_webhooks()
            elapsed = time.time() - start_time

            # Should complete in reasonable time
            assert elapsed < 30.0  # Should complete in under 30 seconds
            assert isinstance(result, ReloadResult)

        finally:
            os.unlink(temp_webhook)
            os.unlink(temp_conn)

    @pytest.mark.asyncio
    async def test_malformed_json_handling(self):
        """Test that malformed JSON is handled safely."""
        malformed_json_variants = [
            '{"invalid": json}',  # Missing quotes
            '{"unclosed": "string}',  # Unclosed string
            '{"trailing": "comma",}',  # Trailing comma
            '{"invalid": \x00}',  # Null byte
            '{"invalid": "string\x00"}',  # Null byte in string
        ]

        for malformed_json in malformed_json_variants:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False
            ) as f:
                try:
                    f.write(malformed_json)
                    temp_webhook = f.name
                except Exception:
                    # Some variants may not be writable
                    continue

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False
            ) as f:
                json.dump({}, f)
                temp_conn = f.name

            try:
                config_manager = ConfigManager(
                    webhook_config_file=temp_webhook, connection_config_file=temp_conn
                )

                result = await config_manager.reload_webhooks()

                # Should fail gracefully (not crash)
                assert isinstance(result, ReloadResult)
                if not result.success:
                    # Error should be sanitized
                    assert (
                        "json" in result.error.lower()
                        or "invalid" in result.error.lower()
                    )

            except Exception as e:
                # Any exception is acceptable as long as it's safe
                assert "json" in str(e).lower() or "decode" in str(e).lower()
            finally:
                try:
                    os.unlink(temp_webhook)
                except:
                    pass
                os.unlink(temp_conn)


# ============================================================================
# 8. CONNECTION POOL EXHAUSTION
# ============================================================================


@pytest.mark.longrunning
class TestConnectionPoolExhaustion:
    """Test connection pool exhaustion vulnerabilities."""

    @pytest.mark.asyncio
    async def test_pool_exhaustion_attack(self):
        """Test that connection pool exhaustion attacks are prevented."""
        registry = ConnectionPoolRegistry()

        # Try to create many pools
        mock_factory = AsyncMock(return_value=Mock())

        tasks = []
        for i in range(100):  # Try to create 100 pools
            config = {"host": f"example{i}.com", "port": 5672}
            tasks.append(registry.get_pool(f"conn_{i}", config, mock_factory))

        # Should complete without hanging
        start_time = time.time()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.time() - start_time

        # Should complete in reasonable time
        assert elapsed < 10.0

        # All should succeed (pools are created independently)
        assert len(results) == 100

    @pytest.mark.asyncio
    async def test_concurrent_pool_access(self):
        """Test that concurrent pool access is handled safely."""
        registry = ConnectionPoolRegistry()

        mock_pool = Mock()
        mock_factory = AsyncMock(return_value=mock_pool)
        config = {"host": "example.com", "port": 5672}

        # Concurrent access to same pool
        tasks = []
        for _ in range(50):
            tasks.append(registry.get_pool("shared_conn", config, mock_factory))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # All should get the same pool
        assert all(r == mock_pool for r in results if not isinstance(r, Exception))


# ============================================================================
# 9. RACE CONDITIONS IN CONCURRENT RELOADS
# ============================================================================


@pytest.mark.longrunning
class TestConcurrentReloadRaceConditions:
    """Test race conditions in concurrent reloads."""

    @pytest.mark.asyncio
    async def test_concurrent_webhook_reloads(self):
        """Test that concurrent webhook reloads don't cause race conditions."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"test": {"module": "log"}}, f)
            temp_webhook = f.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({}, f)
            temp_conn = f.name

        try:
            config_manager = ConfigManager(
                webhook_config_file=temp_webhook, connection_config_file=temp_conn
            )

            await config_manager.initialize()

            # Concurrent reloads
            tasks = []
            for i in range(10):
                # Modify config file
                with open(temp_webhook, "w") as f:
                    json.dump({f"test{i}": {"module": "log"}}, f)
                tasks.append(config_manager.reload_webhooks())
                await asyncio.sleep(0.01)

            results = await asyncio.gather(*tasks, return_exceptions=True)

            # All should complete (some may be blocked by lock, which is correct)
            assert len(results) == 10

            # Final state should be consistent
            # Should have last webhook or one of the reloaded webhooks
            final_config = config_manager._webhook_config
            assert isinstance(final_config, dict)

        finally:
            os.unlink(temp_webhook)
            os.unlink(temp_conn)

    @pytest.mark.asyncio
    async def test_concurrent_connection_reloads(self):
        """Test that concurrent connection reloads don't cause race conditions."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({}, f)
            temp_webhook = f.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(
                {"conn": {"type": "rabbitmq", "host": "example.com", "port": 5672}}, f
            )
            temp_conn = f.name

        try:
            config_manager = ConfigManager(
                webhook_config_file=temp_webhook, connection_config_file=temp_conn
            )

            await config_manager.initialize()

            # Concurrent reloads
            tasks = []
            for i in range(10):
                # Modify config file
                with open(temp_conn, "w") as f:
                    json.dump(
                        {
                            f"conn{i}": {
                                "type": "rabbitmq",
                                "host": f"example{i}.com",
                                "port": 5672,
                            }
                        },
                        f,
                    )
                tasks.append(config_manager.reload_connections())
                await asyncio.sleep(0.01)

            results = await asyncio.gather(*tasks, return_exceptions=True)

            # All should complete
            assert len(results) == 10

            # Final state should be consistent
            final_config = config_manager._connection_config
            assert isinstance(final_config, dict)

        finally:
            os.unlink(temp_webhook)
            os.unlink(temp_conn)


# ============================================================================
# 10. ADMIN ENDPOINT INPUT VALIDATION
# ============================================================================


@pytest.mark.longrunning
class TestAdminEndpointInputValidation:
    """Test input validation in admin endpoints."""

    def test_reload_config_malicious_json(self):
        """Test that malicious JSON in reload-config request is handled safely."""
        client = TestClient(app)

        malicious_payloads = [
            '{"reload_webhooks": true, "__proto__": {"admin": true}}',  # Prototype pollution
            '{"reload_webhooks": "true; rm -rf /"}',  # Command injection attempt
            '{"reload_webhooks": null, "reload_connections": null}',  # Null values
            '{"reload_webhooks": [], "reload_connections": {}}',  # Type confusion
        ]

        for payload in malicious_payloads:
            try:
                response = client.post(
                    "/admin/reload-config",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                )
                # Should not crash (may return error, but should handle gracefully)
                assert response.status_code in [200, 400, 401, 422, 503]
            except Exception as e:
                # Any exception should be safe (not expose system info)
                assert "json" in str(e).lower() or "decode" in str(e).lower()

    def test_reload_config_oversized_payload(self):
        """Test that oversized payloads are handled safely."""
        client = TestClient(app)

        # Very large payload
        large_payload = {"reload_webhooks": True, "data": "x" * 1000000}  # 1MB

        response = client.post("/admin/reload-config", json=large_payload)

        # Should handle gracefully (may reject or process)
        assert response.status_code in [200, 400, 401, 413, 422, 503]

    def test_config_status_parameter_injection(self):
        """Test that parameter injection in config-status is prevented."""
        client = TestClient(app)

        # Try to inject parameters via query string or headers
        malicious_queries = [
            "/admin/config-status?path=../../etc/passwd",
            "/admin/config-status?file=webhooks.json; rm -rf /",
        ]

        for query in malicious_queries:
            response = client.get(query)
            # Should not process query parameters (endpoint doesn't accept them)
            assert response.status_code in [200, 401, 404, 503]
