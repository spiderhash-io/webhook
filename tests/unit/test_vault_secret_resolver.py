"""Tests for VaultSecretResolver."""

from unittest.mock import patch

from src.vault_secret_resolver import VaultSecretResolver


def test_parse_reference_valid():
    """Valid vault reference should parse correctly."""
    parsed = VaultSecretResolver.parse_reference("webhooks/dev#token:default_token")
    assert parsed == ("webhooks/dev", "token", "default_token")


def test_parse_reference_invalid():
    """Invalid vault references should be rejected."""
    assert VaultSecretResolver.parse_reference("webhooks/dev") is None
    assert VaultSecretResolver.parse_reference("webhooks/dev#bad/field") is None
    assert VaultSecretResolver.parse_reference("../bad#token") is None


def test_resolve_reference_disabled_returns_default(monkeypatch):
    """When Vault is disabled, resolver should return default value."""
    resolver = VaultSecretResolver()
    monkeypatch.setenv("SECRETS_BACKEND", "env")
    monkeypatch.delenv("VAULT_ENABLED", raising=False)

    value = resolver.resolve_reference("webhooks/dev#token:default_token")
    assert value == "default_token"


def test_resolve_reference_uses_cache(monkeypatch):
    """Resolved secrets should be cached for repeated lookups."""
    resolver = VaultSecretResolver()
    monkeypatch.setenv("SECRETS_BACKEND", "vault")
    monkeypatch.setenv("VAULT_CACHE_TTL_SECONDS", "300")

    with patch.object(
        resolver, "_read_secret_data", return_value={"token": "cached_value"}
    ) as mock_read:
        first = resolver.resolve_reference("webhooks/dev#token")
        second = resolver.resolve_reference("webhooks/dev#token")

    assert first == "cached_value"
    assert second == "cached_value"
    assert mock_read.call_count == 1


def test_resolve_reference_missing_field_uses_default(monkeypatch):
    """Missing field should return provided inline default."""
    resolver = VaultSecretResolver()
    monkeypatch.setenv("SECRETS_BACKEND", "vault")

    with patch.object(resolver, "_read_secret_data", return_value={"other": "value"}):
        value = resolver.resolve_reference("webhooks/dev#token:inline_default")

    assert value == "inline_default"
