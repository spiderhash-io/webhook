"""
Vault secret resolver used by configuration variable substitution.

Supports references in the format:
    {$vault:path/to/secret#field}
    {$vault:path/to/secret#field:default_value}
"""

import json
import logging
import os
import re
import threading
import time
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

_PATH_PATTERN = re.compile(r"^[a-zA-Z0-9_./-]{1,512}$")
_FIELD_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]{1,128}$")


def _safe_int(value: str, default: int) -> int:
    """Parse integer from env with fallback."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class VaultSecretResolver:
    """Resolves Vault secret references with lightweight in-memory caching."""

    def __init__(self) -> None:
        self._client = None
        self._client_lock = threading.RLock()
        self._cache: Dict[str, Tuple[str, float]] = {}
        self._cache_lock = threading.RLock()
        self._cache_max_size = max(
            1, _safe_int(os.getenv("VAULT_CACHE_MAX_SIZE", "1000"), 1000)
        )

    def is_enabled(self) -> bool:
        """Check whether Vault resolution is enabled by environment variables."""
        secrets_backend = os.getenv("SECRETS_BACKEND", "env").strip().lower()
        if secrets_backend == "vault":
            return True

        vault_enabled = os.getenv("VAULT_ENABLED", "false").strip().lower()
        return vault_enabled in {"1", "true", "yes", "on"}

    def resolve_reference(
        self,
        reference: str,
        default: Optional[str] = None,
        context_key: Optional[str] = None,
    ) -> Optional[str]:
        """
        Resolve a Vault reference to a string value.

        Args:
            reference: Vault reference (path#field or path#field:default).
            default: Optional default value when the secret cannot be read.
            context_key: Optional config key used for contextual logging.

        Returns:
            Resolved string value, default, or None if unresolved.
        """
        parsed = self.parse_reference(reference)
        if parsed is None:
            logger.warning("Invalid Vault reference format: %s", reference)
            return default

        path, field, inline_default = parsed
        effective_default = default if default is not None else inline_default

        if not self.is_enabled():
            return effective_default

        cache_key = f"{path}#{field}"
        cached = self._get_from_cache(cache_key)
        if cached is not None:
            return cached

        try:
            data = self._read_secret_data(path)
        except Exception as exc:
            logger.warning(
                "Vault resolution failed for key '%s' (%s): %s",
                context_key or "unknown",
                cache_key,
                exc.__class__.__name__,
            )
            return effective_default

        if not isinstance(data, dict):
            return effective_default

        value = data.get(field)
        if value is None:
            return effective_default

        if isinstance(value, (dict, list)):
            resolved = json.dumps(value)
        else:
            resolved = str(value)

        self._save_to_cache(cache_key, resolved)
        return resolved

    @staticmethod
    def parse_reference(reference: str) -> Optional[Tuple[str, str, Optional[str]]]:
        """Parse and validate a reference as (path, field, inline_default)."""
        if not isinstance(reference, str):
            return None

        raw = reference.strip()
        if not raw or len(raw) > 1024:
            return None

        if "#" not in raw:
            return None

        path_part, field_part = raw.split("#", 1)
        path = path_part.strip().strip("/")
        if not path or ".." in path or not _PATH_PATTERN.match(path):
            return None

        field_and_default = field_part.strip()
        if not field_and_default:
            return None

        inline_default: Optional[str] = None
        if ":" in field_and_default:
            field, inline_default = field_and_default.split(":", 1)
        else:
            field = field_and_default

        field = field.strip()
        if (
            not field
            or ".." in field
            or "/" in field
            or not _FIELD_PATTERN.match(field)
        ):
            return None

        return path, field, inline_default

    def clear_cache(self) -> None:
        """Clear secret cache."""
        with self._cache_lock:
            self._cache.clear()

    def _get_cache_ttl(self) -> int:
        """Get cache TTL from env."""
        ttl = _safe_int(os.getenv("VAULT_CACHE_TTL_SECONDS", "300"), 300)
        return max(0, ttl)

    def _get_from_cache(self, key: str) -> Optional[str]:
        """Get value from local cache if present and not expired."""
        with self._cache_lock:
            value_and_expiry = self._cache.get(key)
            if value_and_expiry is None:
                return None

            value, expires_at = value_and_expiry
            if expires_at <= time.time():
                self._cache.pop(key, None)
                return None

            return value

    def _save_to_cache(self, key: str, value: str) -> None:
        """Store value in local cache, evicting expired/oldest entries when full."""
        ttl = self._get_cache_ttl()
        if ttl <= 0:
            return

        with self._cache_lock:
            # If key already present, just update it (no size growth)
            if key in self._cache:
                self._cache[key] = (value, time.time() + ttl)
                return

            # Purge expired entries first
            if len(self._cache) >= self._cache_max_size:
                now = time.time()
                expired = [k for k, (_, exp) in self._cache.items() if exp <= now]
                for k in expired:
                    del self._cache[k]

            # If still at capacity, evict entries closest to expiry
            while len(self._cache) >= self._cache_max_size:
                oldest_key = min(self._cache, key=lambda k: self._cache[k][1])
                del self._cache[oldest_key]

            self._cache[key] = (value, time.time() + ttl)

    def _invalidate_client(self) -> None:
        """Invalidate current client (forces re-auth on next call)."""
        with self._client_lock:
            self._client = None

    def _read_secret_data(self, path: str) -> Dict[str, Any]:
        """Read secret data from Vault with a single retry on auth/client errors."""
        last_error: Optional[Exception] = None

        for _ in range(2):
            try:
                client = self._get_client()
                mount_point = os.getenv("VAULT_MOUNT_POINT", "secret").strip("/")
                kv_version = os.getenv("VAULT_KV_VERSION", "2").strip()

                if kv_version == "1":
                    response = client.secrets.kv.v1.read_secret(
                        path=path, mount_point=mount_point
                    )
                    data = response.get("data", {})
                else:
                    response = client.secrets.kv.v2.read_secret_version(
                        path=path, mount_point=mount_point
                    )
                    data = response.get("data", {}).get("data", {})

                if not isinstance(data, dict):
                    return {}
                return data
            except Exception as exc:
                last_error = exc
                self._invalidate_client()

        if last_error is not None:
            raise last_error

        return {}

    def _get_client(self):
        """Create or return authenticated Vault client."""
        with self._client_lock:
            if self._client is not None:
                return self._client

            self._client = self._create_authenticated_client()
            return self._client

    def _create_authenticated_client(self):
        """Create an authenticated hvac client using token or AppRole."""
        try:
            import hvac
        except ImportError as exc:
            raise RuntimeError(
                "Vault support requires the 'hvac' package to be installed"
            ) from exc

        vault_addr = os.getenv("VAULT_ADDR", "").strip()
        if not vault_addr:
            raise ValueError(
                "VAULT_ADDR is required when Vault secret resolution is enabled"
            )

        verify_raw = os.getenv("VAULT_VERIFY", "true").strip()
        verify_value: Any
        if verify_raw.lower() in {"0", "false", "no", "off"}:
            verify_value = False
        elif verify_raw.lower() in {"1", "true", "yes", "on"}:
            verify_value = True
        else:
            verify_value = verify_raw

        namespace = os.getenv("VAULT_NAMESPACE", "").strip() or None

        timeout = _safe_int(os.getenv("VAULT_TIMEOUT_SECONDS", "10"), 10)
        timeout = max(1, min(timeout, 300))  # Clamp 1-300s

        client_kwargs: Dict[str, Any] = {
            "url": vault_addr,
            "verify": verify_value,
            "timeout": timeout,
        }
        if namespace:
            client_kwargs["namespace"] = namespace

        client = hvac.Client(**client_kwargs)

        token = os.getenv("VAULT_TOKEN", "").strip()
        if token:
            client.token = token
            return client

        role_id = os.getenv("VAULT_ROLE_ID", "").strip()
        secret_id = os.getenv("VAULT_SECRET_ID", "").strip()
        if role_id and secret_id:
            auth_response = client.auth.approle.login(role_id=role_id, secret_id=secret_id)
            auth = auth_response.get("auth", {})
            client_token = auth.get("client_token")
            if client_token:
                client.token = client_token
            return client

        raise ValueError(
            "Vault auth not configured. Set VAULT_TOKEN or both VAULT_ROLE_ID and VAULT_SECRET_ID."
        )


_resolver_instance: Optional[VaultSecretResolver] = None
_resolver_lock = threading.Lock()


def get_vault_secret_resolver() -> VaultSecretResolver:
    """Get global VaultSecretResolver singleton."""
    global _resolver_instance
    if _resolver_instance is None:
        with _resolver_lock:
            if _resolver_instance is None:
                _resolver_instance = VaultSecretResolver()
    return _resolver_instance
