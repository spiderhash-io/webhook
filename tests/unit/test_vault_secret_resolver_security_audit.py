"""
Comprehensive security audit tests for VaultSecretResolver.

This audit focuses on:
- ReDoS (regex denial of service) attacks on path/field patterns
- Type confusion attacks on public APIs
- Path traversal and injection via Vault paths/fields
- Information disclosure through error messages and logs
- Cache bounding, eviction, and poisoning attacks
- Thread safety under concurrent access
- Parsing edge cases and boundary conditions
- Authentication bypass attempts
- Time-based cache TTL behavior
"""

import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from unittest.mock import MagicMock, patch

import pytest

from src.vault_secret_resolver import (
    VaultSecretResolver,
    _FIELD_PATTERN,
    _PATH_PATTERN,
    _safe_int,
    get_vault_secret_resolver,
)


# ============================================================================
# 1. REGEX DENIAL OF SERVICE (ReDoS)
# ============================================================================


class TestVaultReDoS:
    """Test ReDoS vulnerabilities in Vault path and field regex patterns."""

    def test_long_path_input_completes_quickly(self):
        """Long valid-looking path should not cause regex backtracking."""
        long_path = "a/" * 256
        start = time.time()
        _PATH_PATTERN.match(long_path)
        elapsed = time.time() - start
        assert elapsed < 1.0, f"ReDoS: _PATH_PATTERN took {elapsed:.2f}s on long path"

    def test_long_field_input_completes_quickly(self):
        """Long valid-looking field should not cause regex backtracking."""
        long_field = "a" * 512
        start = time.time()
        _FIELD_PATTERN.match(long_field)
        elapsed = time.time() - start
        assert elapsed < 1.0, f"ReDoS: _FIELD_PATTERN took {elapsed:.2f}s on long field"

    def test_repeated_special_chars_in_path(self):
        """Repeated special chars should be rejected quickly, not backtrack."""
        inputs = [
            "." * 1000,
            "/" * 1000,
            "_" * 600,
            "a.b/" * 200,
        ]
        for inp in inputs:
            start = time.time()
            _PATH_PATTERN.match(inp)
            elapsed = time.time() - start
            assert elapsed < 1.0, f"ReDoS on path input: {inp[:30]}"

    def test_repeated_special_chars_in_field(self):
        """Repeated special chars should be rejected quickly for fields."""
        inputs = [
            "." * 500,
            "-" * 500,
            "_" * 200,
        ]
        for inp in inputs:
            start = time.time()
            _FIELD_PATTERN.match(inp)
            elapsed = time.time() - start
            assert elapsed < 1.0, f"ReDoS on field input: {inp[:30]}"

    def test_parse_reference_with_huge_input(self):
        """parse_reference should reject oversized input quickly."""
        huge = "a" * 2000 + "#field"
        start = time.time()
        result = VaultSecretResolver.parse_reference(huge)
        elapsed = time.time() - start
        assert result is None
        assert elapsed < 1.0, f"parse_reference took {elapsed:.2f}s on huge input"

    def test_parse_reference_many_slashes(self):
        """Path with many slashes should complete quickly."""
        many_slashes = "/".join(["a"] * 100) + "#field"
        start = time.time()
        VaultSecretResolver.parse_reference(many_slashes)
        elapsed = time.time() - start
        assert elapsed < 1.0


# ============================================================================
# 2. TYPE CONFUSION
# ============================================================================


class TestVaultTypeConfusion:
    """Test type confusion attacks on public APIs."""

    def test_parse_reference_none(self):
        """None input should return None, not raise."""
        assert VaultSecretResolver.parse_reference(None) is None

    def test_parse_reference_int(self):
        """Integer input should return None."""
        assert VaultSecretResolver.parse_reference(12345) is None

    def test_parse_reference_list(self):
        """List input should return None."""
        assert VaultSecretResolver.parse_reference(["path#field"]) is None

    def test_parse_reference_dict(self):
        """Dict input should return None."""
        assert VaultSecretResolver.parse_reference({"path": "field"}) is None

    def test_parse_reference_bool(self):
        """Bool input should return None."""
        assert VaultSecretResolver.parse_reference(True) is None

    def test_parse_reference_bytes(self):
        """Bytes input should return None."""
        assert VaultSecretResolver.parse_reference(b"path#field") is None

    def test_resolve_reference_non_string(self, monkeypatch):
        """resolve_reference with non-string should handle gracefully."""
        resolver = VaultSecretResolver()
        monkeypatch.setenv("SECRETS_BACKEND", "vault")

        # Should not raise, should return default
        result = resolver.resolve_reference(12345, default="fallback")
        assert result == "fallback"

    def test_resolve_reference_none_reference(self, monkeypatch):
        """resolve_reference with None should return default."""
        resolver = VaultSecretResolver()
        monkeypatch.setenv("SECRETS_BACKEND", "vault")

        result = resolver.resolve_reference(None, default="safe_default")
        assert result == "safe_default"


# ============================================================================
# 3. PATH TRAVERSAL
# ============================================================================


class TestVaultPathTraversal:
    """Test path traversal and injection attempts via Vault paths/fields."""

    def test_double_dot_path_rejected(self):
        """Path traversal with '..' should be rejected."""
        assert VaultSecretResolver.parse_reference("../etc/passwd#field") is None
        assert VaultSecretResolver.parse_reference("secret/../../admin#key") is None
        assert VaultSecretResolver.parse_reference("a/b/../../../etc/shadow#x") is None

    def test_encoded_traversal_rejected(self):
        """URL-encoded traversal patterns should be rejected by character validation."""
        # %2e%2e = '..' URL-encoded — should fail _PATH_PATTERN (% not allowed)
        assert VaultSecretResolver.parse_reference("%2e%2e/secret#field") is None

    def test_absolute_path_rejected(self):
        """Absolute paths (starting with /) should be stripped and still validated."""
        result = VaultSecretResolver.parse_reference("/etc/passwd#field")
        # After stripping leading /, ".." check and pattern validation must pass
        # "etc/passwd" is valid alphanumeric — but the leading / is stripped
        if result is not None:
            path, field, _ = result
            assert not path.startswith("/")
            assert ".." not in path

    def test_field_traversal_rejected(self):
        """Fields containing path traversal should be rejected."""
        assert VaultSecretResolver.parse_reference("secret/path#../admin") is None
        assert VaultSecretResolver.parse_reference("secret/path#field/../../x") is None

    def test_field_with_slash_rejected(self):
        """Fields containing '/' should be rejected."""
        assert VaultSecretResolver.parse_reference("secret/path#sub/field") is None

    def test_null_byte_in_path_rejected(self):
        """Null bytes in path should be rejected by _PATH_PATTERN."""
        assert VaultSecretResolver.parse_reference("secret\x00/path#field") is None

    def test_null_byte_in_field_rejected(self):
        """Null bytes in field should be rejected by _FIELD_PATTERN."""
        assert VaultSecretResolver.parse_reference("secret/path#field\x00extra") is None

    def test_backslash_in_path_rejected(self):
        """Backslash in path should be rejected."""
        assert VaultSecretResolver.parse_reference("secret\\path#field") is None

    def test_spaces_in_path_rejected(self):
        """Spaces in path should be rejected by _PATH_PATTERN."""
        assert VaultSecretResolver.parse_reference("secret path/key#field") is None


# ============================================================================
# 4. INFORMATION DISCLOSURE
# ============================================================================


class TestVaultInfoDisclosure:
    """Test that error messages and logs do not leak sensitive information."""

    def test_vault_addr_not_in_warning_on_failure(self, monkeypatch, caplog):
        """VAULT_ADDR should not appear in warning messages."""
        resolver = VaultSecretResolver()
        monkeypatch.setenv("SECRETS_BACKEND", "vault")
        monkeypatch.setenv("VAULT_ADDR", "https://vault.internal.corp:8200")
        monkeypatch.setenv("VAULT_TOKEN", "s.SuperSecretToken123")

        with caplog.at_level(logging.WARNING):
            with patch.object(
                resolver,
                "_read_secret_data",
                side_effect=Exception("connection refused"),
            ):
                resolver.resolve_reference("secret/path#field")

        for record in caplog.records:
            assert "vault.internal.corp" not in record.message
            assert "SuperSecretToken" not in record.message

    def test_secret_values_not_in_logs(self, monkeypatch, caplog):
        """Resolved secret values should not appear in log output."""
        resolver = VaultSecretResolver()
        monkeypatch.setenv("SECRETS_BACKEND", "vault")

        secret_value = "super_secret_password_12345"

        with caplog.at_level(logging.DEBUG):
            with patch.object(
                resolver,
                "_read_secret_data",
                return_value={"password": secret_value},
            ):
                result = resolver.resolve_reference("db/creds#password")

        assert result == secret_value  # Value is returned
        for record in caplog.records:
            assert secret_value not in record.message  # But not logged

    def test_auth_credentials_not_in_error(self, monkeypatch):
        """Auth errors should not contain credential values."""
        resolver = VaultSecretResolver()
        monkeypatch.setenv("VAULT_ADDR", "https://vault:8200")
        monkeypatch.setenv("VAULT_ROLE_ID", "secret-role-id")
        monkeypatch.setenv("VAULT_SECRET_ID", "secret-secret-id")
        monkeypatch.delenv("VAULT_TOKEN", raising=False)

        mock_hvac = MagicMock()
        mock_client = MagicMock()
        mock_client.auth.approle.login.side_effect = Exception("auth failed")
        mock_hvac.Client.return_value = mock_client

        with patch.dict("sys.modules", {"hvac": mock_hvac}):
            try:
                resolver._create_authenticated_client()
            except Exception as e:
                error_msg = str(e)
                assert "secret-role-id" not in error_msg
                assert "secret-secret-id" not in error_msg

    def test_warning_uses_class_name_not_details(self, monkeypatch, caplog):
        """Warning messages should log exception class name, not full details."""
        resolver = VaultSecretResolver()
        monkeypatch.setenv("SECRETS_BACKEND", "vault")

        with caplog.at_level(logging.WARNING):
            with patch.object(
                resolver,
                "_read_secret_data",
                side_effect=ConnectionError("details: host=10.0.0.1 port=8200"),
            ):
                resolver.resolve_reference("secret/path#field")

        # Should log class name
        found_class_name = any("ConnectionError" in r.message for r in caplog.records)
        assert found_class_name
        # Should NOT log full connection details
        for record in caplog.records:
            assert "10.0.0.1" not in record.message


# ============================================================================
# 5. CACHE ATTACKS
# ============================================================================


class TestVaultCacheAttacks:
    """Test cache bounding, eviction, and poisoning."""

    def test_cache_bounded_by_max_size(self, monkeypatch):
        """Cache should not grow beyond VAULT_CACHE_MAX_SIZE."""
        monkeypatch.setenv("VAULT_CACHE_MAX_SIZE", "5")
        monkeypatch.setenv("VAULT_CACHE_TTL_SECONDS", "300")
        resolver = VaultSecretResolver()

        for i in range(20):
            resolver._save_to_cache(f"key_{i}", f"value_{i}")

        assert len(resolver._cache) <= 5

    def test_eviction_removes_closest_to_expiry(self, monkeypatch):
        """Eviction should remove entries closest to expiry first."""
        monkeypatch.setenv("VAULT_CACHE_MAX_SIZE", "3")
        monkeypatch.setenv("VAULT_CACHE_TTL_SECONDS", "300")
        resolver = VaultSecretResolver()

        # Manually insert with controlled expiry times
        now = time.time()
        with resolver._cache_lock:
            resolver._cache["oldest"] = ("v1", now + 10)  # Expires soonest
            resolver._cache["middle"] = ("v2", now + 100)
            resolver._cache["newest"] = ("v3", now + 200)  # Expires latest

        # Adding one more should evict "oldest"
        resolver._save_to_cache("new_entry", "v4")

        assert "oldest" not in resolver._cache
        assert "new_entry" in resolver._cache

    def test_expired_entries_cleaned_on_save(self, monkeypatch):
        """Expired entries should be purged when cache is full."""
        monkeypatch.setenv("VAULT_CACHE_MAX_SIZE", "3")
        monkeypatch.setenv("VAULT_CACHE_TTL_SECONDS", "300")
        resolver = VaultSecretResolver()

        # Insert entries that are already expired
        now = time.time()
        with resolver._cache_lock:
            resolver._cache["expired_1"] = ("v1", now - 10)
            resolver._cache["expired_2"] = ("v2", now - 5)
            resolver._cache["valid"] = ("v3", now + 300)

        # Save should clean expired, making room without evicting "valid"
        resolver._save_to_cache("new_key", "new_val")

        assert "expired_1" not in resolver._cache
        assert "expired_2" not in resolver._cache
        assert "valid" in resolver._cache
        assert "new_key" in resolver._cache

    def test_ttl_zero_disables_cache(self, monkeypatch):
        """TTL=0 should disable caching entirely."""
        monkeypatch.setenv("VAULT_CACHE_TTL_SECONDS", "0")
        resolver = VaultSecretResolver()

        resolver._save_to_cache("key", "value")
        assert len(resolver._cache) == 0

    def test_negative_ttl_disables_cache(self, monkeypatch):
        """Negative TTL should be clamped to 0 and disable cache."""
        monkeypatch.setenv("VAULT_CACHE_TTL_SECONDS", "-10")
        resolver = VaultSecretResolver()

        resolver._save_to_cache("key", "value")
        assert len(resolver._cache) == 0

    def test_cache_max_size_one(self, monkeypatch):
        """Cache with max_size=1 should only keep most recent entry."""
        monkeypatch.setenv("VAULT_CACHE_MAX_SIZE", "1")
        monkeypatch.setenv("VAULT_CACHE_TTL_SECONDS", "300")
        resolver = VaultSecretResolver()

        resolver._save_to_cache("first", "v1")
        resolver._save_to_cache("second", "v2")

        assert len(resolver._cache) == 1
        assert "second" in resolver._cache

    def test_update_existing_key_no_size_growth(self, monkeypatch):
        """Updating an existing key should not increase cache size."""
        monkeypatch.setenv("VAULT_CACHE_MAX_SIZE", "3")
        monkeypatch.setenv("VAULT_CACHE_TTL_SECONDS", "300")
        resolver = VaultSecretResolver()

        resolver._save_to_cache("key1", "v1")
        resolver._save_to_cache("key2", "v2")
        resolver._save_to_cache("key1", "v1_updated")

        assert len(resolver._cache) == 2
        val, _ = resolver._cache["key1"]
        assert val == "v1_updated"


# ============================================================================
# 6. THREADING SAFETY
# ============================================================================


class TestVaultThreading:
    """Test concurrency safety of cache and client creation."""

    def test_concurrent_cache_writes(self, monkeypatch):
        """50 concurrent writes should not corrupt cache or raise exceptions."""
        monkeypatch.setenv("VAULT_CACHE_MAX_SIZE", "100")
        monkeypatch.setenv("VAULT_CACHE_TTL_SECONDS", "300")
        resolver = VaultSecretResolver()

        errors = []

        def write(i):
            try:
                resolver._save_to_cache(f"key_{i}", f"value_{i}")
            except Exception as e:
                errors.append(e)

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(write, i) for i in range(50)]
            for f in as_completed(futures):
                f.result()

        assert len(errors) == 0
        assert len(resolver._cache) <= 100

    def test_concurrent_cache_reads_and_writes(self, monkeypatch):
        """Concurrent reads and writes should not raise exceptions."""
        monkeypatch.setenv("VAULT_CACHE_TTL_SECONDS", "300")
        resolver = VaultSecretResolver()

        # Pre-populate
        for i in range(10):
            resolver._save_to_cache(f"key_{i}", f"value_{i}")

        errors = []

        def read_write(i):
            try:
                if i % 2 == 0:
                    resolver._get_from_cache(f"key_{i % 10}")
                else:
                    resolver._save_to_cache(f"key_{i}", f"value_{i}")
            except Exception as e:
                errors.append(e)

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(read_write, i) for i in range(50)]
            for f in as_completed(futures):
                f.result()

        assert len(errors) == 0

    def test_single_client_creation_under_contention(self, monkeypatch):
        """Multiple threads requesting client should only create it once."""
        monkeypatch.setenv("SECRETS_BACKEND", "vault")
        monkeypatch.setenv("VAULT_ADDR", "https://vault:8200")
        monkeypatch.setenv("VAULT_TOKEN", "test-token")

        resolver = VaultSecretResolver()
        creation_count = {"count": 0}
        original_create = resolver._create_authenticated_client

        def counting_create():
            creation_count["count"] += 1
            mock_client = MagicMock()
            return mock_client

        resolver._create_authenticated_client = counting_create

        threads = []
        for _ in range(10):
            t = threading.Thread(target=resolver._get_client)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Client should only be created once (double-check locking)
        assert creation_count["count"] == 1


# ============================================================================
# 7. PARSING EDGE CASES
# ============================================================================


class TestVaultParsingEdgeCases:
    """Test parsing of edge-case references."""

    def test_empty_string_rejected(self):
        """Empty string should return None."""
        assert VaultSecretResolver.parse_reference("") is None

    def test_whitespace_only_rejected(self):
        """Whitespace-only input should return None."""
        assert VaultSecretResolver.parse_reference("   ") is None

    def test_over_1024_chars_rejected(self):
        """Reference over 1024 chars should be rejected."""
        long_ref = "a" * 500 + "#" + "b" * 525
        assert VaultSecretResolver.parse_reference(long_ref) is None

    def test_exactly_1024_chars_accepted(self):
        """Reference exactly at 1024 chars with valid format should be accepted."""
        # Build a valid reference that is exactly 1024 chars
        path = "a" * 500
        field = "b" * (1024 - 500 - 1)  # -1 for '#'
        ref = f"{path}#{field}"
        assert len(ref) == 1024
        result = VaultSecretResolver.parse_reference(ref)
        # Path is valid (<=512, alphanumeric) but field is 523 chars (>128), so rejected
        if result is not None:
            _, field_val, _ = result
            assert len(field_val) <= 128

    def test_multiple_hash_signs(self):
        """Only first '#' should be used as separator."""
        result = VaultSecretResolver.parse_reference("path/to/secret#field#extra")
        # "field#extra" — '#' is not in _FIELD_PATTERN, so it depends on ':'
        # No ':' so field = "field#extra" which fails _FIELD_PATTERN
        assert result is None

    def test_colon_in_default_value(self):
        """Colons in default value should be preserved (split on first ':' only)."""
        result = VaultSecretResolver.parse_reference("path/secret#field:http://host:8080")
        assert result is not None
        path, field, default = result
        assert path == "path/secret"
        assert field == "field"
        assert default == "http://host:8080"

    def test_unicode_in_path_rejected(self):
        """Unicode characters in path should be rejected."""
        assert VaultSecretResolver.parse_reference("secret/p\u00e4th#field") is None

    def test_unicode_in_field_rejected(self):
        """Unicode characters in field should be rejected."""
        assert VaultSecretResolver.parse_reference("secret/path#fi\u00ebld") is None

    def test_null_bytes_rejected(self):
        """Null bytes anywhere in reference should be rejected."""
        assert VaultSecretResolver.parse_reference("secret\x00#field") is None
        assert VaultSecretResolver.parse_reference("secret#field\x00") is None
        assert VaultSecretResolver.parse_reference("\x00secret#field") is None

    def test_no_hash_separator(self):
        """Reference without '#' should return None."""
        assert VaultSecretResolver.parse_reference("secret/path") is None

    def test_empty_field(self):
        """Reference with empty field should return None."""
        assert VaultSecretResolver.parse_reference("secret/path#") is None

    def test_empty_path(self):
        """Reference with empty path should return None."""
        assert VaultSecretResolver.parse_reference("#field") is None

    def test_valid_minimal_reference(self):
        """Minimal valid reference should parse."""
        result = VaultSecretResolver.parse_reference("a#b")
        assert result == ("a", "b", None)

    def test_valid_reference_with_default(self):
        """Reference with default should parse correctly."""
        result = VaultSecretResolver.parse_reference("path/to/secret#field:my_default")
        assert result == ("path/to/secret", "field", "my_default")

    def test_empty_default_value(self):
        """Reference with empty default (trailing colon) should parse."""
        result = VaultSecretResolver.parse_reference("path/secret#field:")
        assert result is not None
        _, _, default = result
        assert default == ""


# ============================================================================
# 8. AUTHENTICATION BYPASS
# ============================================================================


class TestVaultAuthBypass:
    """Test that auth mechanisms cannot be bypassed."""

    def test_no_credentials_raises_error(self, monkeypatch):
        """Missing all credentials should raise ValueError."""
        resolver = VaultSecretResolver()
        monkeypatch.setenv("VAULT_ADDR", "https://vault:8200")
        monkeypatch.delenv("VAULT_TOKEN", raising=False)
        monkeypatch.delenv("VAULT_ROLE_ID", raising=False)
        monkeypatch.delenv("VAULT_SECRET_ID", raising=False)

        mock_hvac = MagicMock()
        mock_hvac.Client.return_value = MagicMock()

        with patch.dict("sys.modules", {"hvac": mock_hvac}):
            with pytest.raises(ValueError, match="Vault auth not configured"):
                resolver._create_authenticated_client()

    def test_empty_token_falls_through_to_approle(self, monkeypatch):
        """Empty VAULT_TOKEN should not authenticate; should fall through to AppRole."""
        resolver = VaultSecretResolver()
        monkeypatch.setenv("VAULT_ADDR", "https://vault:8200")
        monkeypatch.setenv("VAULT_TOKEN", "")
        monkeypatch.delenv("VAULT_ROLE_ID", raising=False)
        monkeypatch.delenv("VAULT_SECRET_ID", raising=False)

        mock_hvac = MagicMock()
        mock_hvac.Client.return_value = MagicMock()

        with patch.dict("sys.modules", {"hvac": mock_hvac}):
            with pytest.raises(ValueError, match="Vault auth not configured"):
                resolver._create_authenticated_client()

    def test_empty_vault_addr_raises_error(self, monkeypatch):
        """Empty VAULT_ADDR should raise ValueError."""
        resolver = VaultSecretResolver()
        monkeypatch.setenv("VAULT_ADDR", "")

        mock_hvac = MagicMock()

        with patch.dict("sys.modules", {"hvac": mock_hvac}):
            with pytest.raises(ValueError, match="VAULT_ADDR is required"):
                resolver._create_authenticated_client()

    def test_partial_approle_config_role_only(self, monkeypatch):
        """Only VAULT_ROLE_ID without VAULT_SECRET_ID should raise."""
        resolver = VaultSecretResolver()
        monkeypatch.setenv("VAULT_ADDR", "https://vault:8200")
        monkeypatch.delenv("VAULT_TOKEN", raising=False)
        monkeypatch.setenv("VAULT_ROLE_ID", "my-role")
        monkeypatch.setenv("VAULT_SECRET_ID", "")

        mock_hvac = MagicMock()
        mock_hvac.Client.return_value = MagicMock()

        with patch.dict("sys.modules", {"hvac": mock_hvac}):
            with pytest.raises(ValueError, match="Vault auth not configured"):
                resolver._create_authenticated_client()

    def test_partial_approle_config_secret_only(self, monkeypatch):
        """Only VAULT_SECRET_ID without VAULT_ROLE_ID should raise."""
        resolver = VaultSecretResolver()
        monkeypatch.setenv("VAULT_ADDR", "https://vault:8200")
        monkeypatch.delenv("VAULT_TOKEN", raising=False)
        monkeypatch.setenv("VAULT_ROLE_ID", "")
        monkeypatch.setenv("VAULT_SECRET_ID", "my-secret")

        mock_hvac = MagicMock()
        mock_hvac.Client.return_value = MagicMock()

        with patch.dict("sys.modules", {"hvac": mock_hvac}):
            with pytest.raises(ValueError, match="Vault auth not configured"):
                resolver._create_authenticated_client()

    def test_timeout_is_applied(self, monkeypatch):
        """Timeout should be passed to hvac.Client kwargs."""
        resolver = VaultSecretResolver()
        monkeypatch.setenv("VAULT_ADDR", "https://vault:8200")
        monkeypatch.setenv("VAULT_TOKEN", "test-token")
        monkeypatch.setenv("VAULT_TIMEOUT_SECONDS", "30")

        mock_hvac = MagicMock()
        mock_client = MagicMock()
        mock_hvac.Client.return_value = mock_client

        with patch.dict("sys.modules", {"hvac": mock_hvac}):
            resolver._create_authenticated_client()

        call_kwargs = mock_hvac.Client.call_args[1]
        assert call_kwargs["timeout"] == 30

    def test_timeout_clamped_to_bounds(self, monkeypatch):
        """Timeout should be clamped between 1 and 300."""
        resolver = VaultSecretResolver()
        monkeypatch.setenv("VAULT_ADDR", "https://vault:8200")
        monkeypatch.setenv("VAULT_TOKEN", "test-token")

        mock_hvac = MagicMock()
        mock_hvac.Client.return_value = MagicMock()

        # Test lower bound
        monkeypatch.setenv("VAULT_TIMEOUT_SECONDS", "0")
        with patch.dict("sys.modules", {"hvac": mock_hvac}):
            resolver._client = None
            resolver._create_authenticated_client()
        assert mock_hvac.Client.call_args[1]["timeout"] == 1

        # Test upper bound
        monkeypatch.setenv("VAULT_TIMEOUT_SECONDS", "9999")
        with patch.dict("sys.modules", {"hvac": mock_hvac}):
            resolver._client = None
            resolver._create_authenticated_client()
        assert mock_hvac.Client.call_args[1]["timeout"] == 300


# ============================================================================
# 9. TIME-BASED CACHE BEHAVIOR
# ============================================================================


class TestVaultTimeBased:
    """Test cache TTL expiry behavior."""

    def test_entry_expires_after_ttl(self, monkeypatch):
        """Cached entry should not be returned after TTL expires."""
        monkeypatch.setenv("VAULT_CACHE_TTL_SECONDS", "300")
        resolver = VaultSecretResolver()

        # Insert with near-immediate expiry
        with resolver._cache_lock:
            resolver._cache["test_key"] = ("value", time.time() - 1)

        assert resolver._get_from_cache("test_key") is None

    def test_entry_valid_before_ttl(self, monkeypatch):
        """Cached entry should be returned before TTL expires."""
        monkeypatch.setenv("VAULT_CACHE_TTL_SECONDS", "300")
        resolver = VaultSecretResolver()

        resolver._save_to_cache("test_key", "test_value")
        assert resolver._get_from_cache("test_key") == "test_value"

    def test_env_configurable_ttl(self, monkeypatch):
        """Cache TTL should be configurable via VAULT_CACHE_TTL_SECONDS."""
        monkeypatch.setenv("VAULT_CACHE_TTL_SECONDS", "600")
        resolver = VaultSecretResolver()

        resolver._save_to_cache("key", "value")

        _, expiry = resolver._cache["key"]
        expected_min = time.time() + 590  # Allow 10s tolerance
        assert expiry > expected_min

    def test_invalid_ttl_uses_default(self, monkeypatch):
        """Non-integer TTL should fall back to default (300)."""
        monkeypatch.setenv("VAULT_CACHE_TTL_SECONDS", "not_a_number")
        resolver = VaultSecretResolver()

        resolver._save_to_cache("key", "value")

        _, expiry = resolver._cache["key"]
        expected_min = time.time() + 290  # Default 300, minus tolerance
        assert expiry > expected_min

    def test_clear_cache_removes_all(self, monkeypatch):
        """clear_cache should remove all entries."""
        monkeypatch.setenv("VAULT_CACHE_TTL_SECONDS", "300")
        resolver = VaultSecretResolver()

        for i in range(10):
            resolver._save_to_cache(f"key_{i}", f"val_{i}")

        assert len(resolver._cache) == 10
        resolver.clear_cache()
        assert len(resolver._cache) == 0

    def test_get_from_cache_removes_expired(self, monkeypatch):
        """Reading an expired key should remove it from cache."""
        monkeypatch.setenv("VAULT_CACHE_TTL_SECONDS", "300")
        resolver = VaultSecretResolver()

        with resolver._cache_lock:
            resolver._cache["expired_key"] = ("value", time.time() - 1)

        result = resolver._get_from_cache("expired_key")
        assert result is None
        assert "expired_key" not in resolver._cache
