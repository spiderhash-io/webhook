# Unified Configuration System - Multi-Backend Support

> **Flexible configuration system supporting JSON files, etcd, and Vault with runtime backend selection**
>
> Use JSON for development, etcd for production, or Vault for secrets - all with the same code!

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Implementation](#implementation)
4. [Usage Examples](#usage-examples)
5. [Deployment Scenarios](#deployment-scenarios)
6. [Migration Path](#migration-path)

---

## Overview

### The Goal

**One codebase that works with multiple config backends**:

```python
# Same code works with ANY backend!
config_manager = ConfigManager.from_env()

# Development: Loads from webhooks.json
# Staging: Loads from etcd
# Production: Loads from etcd + Vault

config = await config_manager.get_webhook_config("wh_abc123")
```

### Supported Backends

```
┌─────────────────────────────────────────────────────┐
│           Unified ConfigManager Interface            │
├─────────────────────────────────────────────────────┤
│                                                      │
│  get_webhook_config(webhook_id)                     │
│  create_webhook_config(webhook_id, config)          │
│  update_webhook_config(webhook_id, config)          │
│  delete_webhook_config(webhook_id)                  │
│  list_webhook_ids()                                 │
│                                                      │
└──────────────┬──────────────────────────────────────┘
               │
    ┌──────────┴──────────┬─────────────┬─────────────┐
    │                     │             │             │
    ▼                     ▼             ▼             ▼
┌─────────┐      ┌──────────────┐  ┌────────┐  ┌──────────┐
│  JSON   │      │     etcd     │  │ Vault  │  │  Hybrid  │
│Provider │      │   Provider   │  │Provider│  │ Provider │
│         │      │              │  │        │  │(etcd+    │
│• Local  │      │• Distributed │  │• Secure│  │ Vault)   │
│• Simple │      │• Real-time   │  │• Audit │  │          │
│• Dev    │      │• Multi-inst  │  │• Rotate│  │• Best of │
│         │      │              │  │        │  │  both    │
└─────────┘      └──────────────┘  └────────┘  └──────────┘
```

### Backend Selection (Environment-Driven)

```bash
# Development: JSON files
export CONFIG_BACKEND=file
export SECRETS_BACKEND=env

# Staging: etcd for config
export CONFIG_BACKEND=etcd
export ETCD_HOST=etcd.staging.local

# Production: etcd + Vault
export CONFIG_BACKEND=etcd
export SECRETS_BACKEND=vault
export ETCD_HOST=etcd.prod.local
export VAULT_ADDR=https://vault.prod.local
```

---

## Architecture

### Abstraction Layer

```python
from abc import ABC, abstractmethod

class ConfigProvider(ABC):
    """Abstract base class for configuration providers."""

    @abstractmethod
    async def get_config(self, key: str) -> Optional[dict]:
        """Get configuration by key."""
        pass

    @abstractmethod
    async def set_config(self, key: str, config: dict) -> bool:
        """Set configuration."""
        pass

    @abstractmethod
    async def delete_config(self, key: str) -> bool:
        """Delete configuration."""
        pass

    @abstractmethod
    async def list_keys(self, prefix: str = "") -> list[str]:
        """List all configuration keys."""
        pass

    @abstractmethod
    async def watch_changes(self, callback: Callable) -> None:
        """Watch for configuration changes."""
        pass


class SecretProvider(ABC):
    """Abstract base class for secret providers."""

    @abstractmethod
    async def get_secret(self, path: str) -> Optional[dict]:
        """Get secret by path."""
        pass

    @abstractmethod
    async def set_secret(self, path: str, secret: dict) -> bool:
        """Set secret."""
        pass

    @abstractmethod
    async def delete_secret(self, path: str) -> bool:
        """Delete secret."""
        pass
```

### Component Diagram

```
┌────────────────────────────────────────────────────────┐
│              Application Layer                          │
│  (FastAPI webhook receiver)                            │
└─────────────────────┬──────────────────────────────────┘
                      │
                      ▼
┌────────────────────────────────────────────────────────┐
│          UnifiedConfigManager                           │
│  - Combines ConfigProvider + SecretProvider            │
│  - Merges config + secrets                             │
│  - Caching layer                                        │
└─────────────────────┬──────────────────────────────────┘
                      │
        ┌─────────────┴─────────────┐
        │                           │
        ▼                           ▼
┌──────────────┐          ┌─────────────────┐
│ConfigProvider│          │ SecretProvider  │
│(etcd/file)   │          │ (Vault/env)     │
└──────────────┘          └─────────────────┘
```

---

## Implementation

### Step 1: Abstract Interfaces

Create `src/config/providers/base.py`:

```python
"""
Base interfaces for configuration and secret providers.
"""

from abc import ABC, abstractmethod
from typing import Optional, Callable, Any
import asyncio


class ConfigProvider(ABC):
    """Abstract configuration provider."""

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize provider (connections, load initial data)."""
        pass

    @abstractmethod
    async def get_config(self, key: str) -> Optional[dict]:
        """Get configuration by key."""
        pass

    @abstractmethod
    async def set_config(self, key: str, config: dict, ttl: Optional[int] = None) -> bool:
        """Set configuration with optional TTL."""
        pass

    @abstractmethod
    async def delete_config(self, key: str) -> bool:
        """Delete configuration."""
        pass

    @abstractmethod
    async def list_keys(self, prefix: str = "") -> list[str]:
        """List configuration keys with optional prefix."""
        pass

    @abstractmethod
    async def watch_changes(self, prefix: str, callback: Callable) -> None:
        """Watch for configuration changes."""
        pass

    @abstractmethod
    async def shutdown(self) -> None:
        """Cleanup and shutdown."""
        pass


class SecretProvider(ABC):
    """Abstract secret provider."""

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize provider."""
        pass

    @abstractmethod
    async def get_secret(self, path: str) -> Optional[dict]:
        """Get secret by path."""
        pass

    @abstractmethod
    async def set_secret(self, path: str, secret: dict) -> bool:
        """Set secret."""
        pass

    @abstractmethod
    async def delete_secret(self, path: str) -> bool:
        """Delete secret."""
        pass

    @abstractmethod
    async def shutdown(self) -> None:
        """Cleanup and shutdown."""
        pass
```

### Step 2: File-Based Provider

Create `src/config/providers/file_provider.py`:

```python
"""
File-based configuration provider (JSON + .env).

For development and simple deployments.
"""

import json
import os
import asyncio
import logging
from typing import Optional, Callable
from pathlib import Path
from datetime import datetime

from .base import ConfigProvider, SecretProvider

logger = logging.getLogger(__name__)


class FileConfigProvider(ConfigProvider):
    """
    Configuration provider using local JSON file.

    Supports:
    - Loading from webhooks.json
    - Environment variable substitution
    - File watching (polling-based)
    """

    def __init__(self, config_file: str = "webhooks.json"):
        self.config_file = config_file
        self._configs: dict = {}
        self._watch_task: Optional[asyncio.Task] = None
        self._last_modified: Optional[float] = None

    async def initialize(self) -> None:
        """Load configuration from file."""
        await self._load_from_file()
        logger.info(f"FileConfigProvider initialized from {self.config_file}")

    async def _load_from_file(self) -> None:
        """Load and parse JSON file."""
        if not os.path.exists(self.config_file):
            logger.warning(f"Config file not found: {self.config_file}")
            self._configs = {}
            return

        try:
            with open(self.config_file, 'r') as f:
                self._configs = json.load(f)

            # Update last modified time
            self._last_modified = os.path.getmtime(self.config_file)

            logger.info(f"Loaded {len(self._configs)} configs from {self.config_file}")
        except Exception as e:
            logger.error(f"Failed to load config file: {e}")
            self._configs = {}

    async def get_config(self, key: str) -> Optional[dict]:
        """Get configuration by webhook ID."""
        return self._configs.get(key)

    async def set_config(self, key: str, config: dict, ttl: Optional[int] = None) -> bool:
        """Set configuration and save to file."""
        self._configs[key] = config

        # Save to file
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self._configs, f, indent=2)
            logger.info(f"Saved config for {key} to {self.config_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            return False

    async def delete_config(self, key: str) -> bool:
        """Delete configuration and update file."""
        if key in self._configs:
            del self._configs[key]

            # Save to file
            try:
                with open(self.config_file, 'w') as f:
                    json.dump(self._configs, f, indent=2)
                logger.info(f"Deleted config for {key}")
                return True
            except Exception as e:
                logger.error(f"Failed to delete config: {e}")
                return False
        return False

    async def list_keys(self, prefix: str = "") -> list[str]:
        """List all webhook IDs matching prefix."""
        if prefix:
            return [k for k in self._configs.keys() if k.startswith(prefix)]
        return list(self._configs.keys())

    async def watch_changes(self, prefix: str, callback: Callable) -> None:
        """Watch file for changes (polling-based)."""
        if self._watch_task:
            return  # Already watching

        async def _watch_loop():
            while True:
                try:
                    await asyncio.sleep(5)  # Check every 5 seconds

                    if not os.path.exists(self.config_file):
                        continue

                    current_mtime = os.path.getmtime(self.config_file)

                    if self._last_modified and current_mtime > self._last_modified:
                        logger.info("Config file changed, reloading...")

                        old_configs = self._configs.copy()
                        await self._load_from_file()

                        # Detect changes
                        for key in self._configs:
                            if key not in old_configs:
                                await callback('create', key, self._configs[key])
                            elif self._configs[key] != old_configs.get(key):
                                await callback('update', key, self._configs[key])

                        # Detect deletions
                        for key in old_configs:
                            if key not in self._configs:
                                await callback('delete', key, old_configs[key])

                except Exception as e:
                    logger.error(f"Watch error: {e}")

        self._watch_task = asyncio.create_task(_watch_loop())
        logger.info(f"Started watching {self.config_file}")

    async def shutdown(self) -> None:
        """Stop watching and cleanup."""
        if self._watch_task:
            self._watch_task.cancel()
            try:
                await self._watch_task
            except asyncio.CancelledError:
                pass
        logger.info("FileConfigProvider shutdown")


class EnvSecretProvider(SecretProvider):
    """
    Secret provider using environment variables.

    For development and simple deployments.
    Secrets stored as: WEBHOOK_{WEBHOOK_ID}_{SECRET_TYPE}
    """

    async def initialize(self) -> None:
        """No initialization needed for env vars."""
        logger.info("EnvSecretProvider initialized")

    async def get_secret(self, path: str) -> Optional[dict]:
        """
        Get secret from environment variables.

        Path format: webhooks/wh_abc123/secrets
        Looks for:
        - WEBHOOK_WH_ABC123_TOKEN
        - WEBHOOK_WH_ABC123_CHANNEL_TOKEN
        - WEBHOOK_WH_ABC123_HMAC_SECRET
        """
        # Extract webhook ID from path
        parts = path.split('/')
        if len(parts) < 2:
            return None

        webhook_id = parts[1].upper().replace('-', '_')

        # Build secret dict from env vars
        secrets = {}

        # Bearer token
        token_key = f"WEBHOOK_{webhook_id}_TOKEN"
        if token_key in os.environ:
            secrets['bearer-token'] = os.environ[token_key]

        # Channel token
        channel_key = f"WEBHOOK_{webhook_id}_CHANNEL_TOKEN"
        if channel_key in os.environ:
            secrets['channel-token'] = os.environ[channel_key]

        # HMAC secret
        hmac_key = f"WEBHOOK_{webhook_id}_HMAC_SECRET"
        if hmac_key in os.environ:
            secrets['hmac-secret'] = os.environ[hmac_key]

        return secrets if secrets else None

    async def set_secret(self, path: str, secret: dict) -> bool:
        """Cannot set env vars at runtime."""
        logger.warning("EnvSecretProvider.set_secret() not supported")
        return False

    async def delete_secret(self, path: str) -> bool:
        """Cannot delete env vars at runtime."""
        logger.warning("EnvSecretProvider.delete_secret() not supported")
        return False

    async def shutdown(self) -> None:
        """No cleanup needed."""
        pass
```

### Step 3: etcd Provider

Create `src/config/providers/etcd_provider.py`:

```python
"""
etcd-based configuration provider.

For production multi-instance deployments.
"""

import json
import asyncio
import logging
from typing import Optional, Callable

import etcd3
from etcd3.events import PutEvent, DeleteEvent

from .base import ConfigProvider

logger = logging.getLogger(__name__)


class EtcdConfigProvider(ConfigProvider):
    """
    Configuration provider using etcd.

    Features:
    - Distributed storage
    - Real-time watch
    - Atomic operations
    """

    def __init__(
        self,
        host: str = 'localhost',
        port: int = 2379,
        prefix: str = '/webhooks/configs/'
    ):
        self.host = host
        self.port = port
        self.prefix = prefix
        self.client: Optional[etcd3.Etcd3Client] = None
        self._watch_task: Optional[asyncio.Task] = None
        self._cache: dict = {}

    async def initialize(self) -> None:
        """Connect to etcd and load configs."""
        self.client = etcd3.client(host=self.host, port=self.port)

        # Load all existing configs
        await self._load_all_configs()

        logger.info(f"EtcdConfigProvider initialized (host={self.host}:{self.port})")

    async def _load_all_configs(self) -> None:
        """Load all configs from etcd into cache."""
        configs = await asyncio.to_thread(
            self.client.get_prefix,
            self.prefix
        )

        for value, metadata in configs:
            key = metadata.key.decode('utf-8').replace(self.prefix, '')
            try:
                config = json.loads(value.decode('utf-8'))
                self._cache[key] = config
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON for {key}: {e}")

        logger.info(f"Loaded {len(self._cache)} configs from etcd")

    async def get_config(self, key: str) -> Optional[dict]:
        """Get config from cache."""
        return self._cache.get(key)

    async def set_config(self, key: str, config: dict, ttl: Optional[int] = None) -> bool:
        """Set config in etcd."""
        etcd_key = f"{self.prefix}{key}"
        value = json.dumps(config)

        try:
            if ttl:
                lease = await asyncio.to_thread(self.client.lease, ttl)
                await asyncio.to_thread(
                    self.client.put,
                    etcd_key,
                    value,
                    lease=lease
                )
            else:
                await asyncio.to_thread(self.client.put, etcd_key, value)

            logger.info(f"Set config for {key} in etcd")
            return True
        except Exception as e:
            logger.error(f"Failed to set config: {e}")
            return False

    async def delete_config(self, key: str) -> bool:
        """Delete config from etcd."""
        etcd_key = f"{self.prefix}{key}"

        try:
            deleted = await asyncio.to_thread(self.client.delete, etcd_key)
            logger.info(f"Deleted config for {key}")
            return bool(deleted)
        except Exception as e:
            logger.error(f"Failed to delete config: {e}")
            return False

    async def list_keys(self, prefix: str = "") -> list[str]:
        """List config keys."""
        if prefix:
            return [k for k in self._cache.keys() if k.startswith(prefix)]
        return list(self._cache.keys())

    async def watch_changes(self, prefix: str, callback: Callable) -> None:
        """Watch etcd for changes."""
        if self._watch_task:
            return

        async def _watch_loop():
            watch_prefix = f"{self.prefix}{prefix}"
            watch_id, events_iterator = await asyncio.to_thread(
                self.client.watch_prefix,
                watch_prefix
            )

            try:
                for event in events_iterator:
                    await self._handle_event(event, callback)
            except Exception as e:
                logger.error(f"Watch error: {e}")

        self._watch_task = asyncio.create_task(_watch_loop())
        logger.info(f"Started watching etcd prefix: {self.prefix}")

    async def _handle_event(self, event, callback):
        """Handle watch event."""
        key = event.key.decode('utf-8').replace(self.prefix, '')

        if isinstance(event, PutEvent):
            try:
                config = json.loads(event.value.decode('utf-8'))
                change_type = 'update' if key in self._cache else 'create'
                self._cache[key] = config
                await callback(change_type, key, config)
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON in event: {e}")

        elif isinstance(event, DeleteEvent):
            if key in self._cache:
                config = self._cache.pop(key)
                await callback('delete', key, config)

    async def shutdown(self) -> None:
        """Shutdown etcd connection."""
        if self._watch_task:
            self._watch_task.cancel()
            try:
                await self._watch_task
            except asyncio.CancelledError:
                pass

        if self.client:
            await asyncio.to_thread(self.client.close)

        logger.info("EtcdConfigProvider shutdown")
```

### Step 4: Vault Provider

Create `src/config/providers/vault_provider.py`:

```python
"""
Vault-based secret provider.

For production secret management.
"""

import asyncio
import logging
from typing import Optional

import hvac

from .base import SecretProvider

logger = logging.getLogger(__name__)


class VaultSecretProvider(SecretProvider):
    """
    Secret provider using HashiCorp Vault.

    Features:
    - Encrypted storage
    - Audit logging
    - Secret rotation
    """

    def __init__(
        self,
        vault_addr: str,
        role_id: str,
        secret_id: str,
        mount_point: str = 'webhooks'
    ):
        self.vault_addr = vault_addr
        self.role_id = role_id
        self.secret_id = secret_id
        self.mount_point = mount_point
        self.client: Optional[hvac.Client] = None

    async def initialize(self) -> None:
        """Authenticate with Vault."""
        self.client = hvac.Client(url=self.vault_addr)

        # Authenticate with AppRole
        await asyncio.to_thread(
            self.client.auth.approle.login,
            role_id=self.role_id,
            secret_id=self.secret_id
        )

        logger.info(f"VaultSecretProvider initialized (addr={self.vault_addr})")

    async def get_secret(self, path: str) -> Optional[dict]:
        """Get secret from Vault."""
        try:
            response = await asyncio.to_thread(
                self.client.secrets.kv.v2.read_secret_version,
                path=path,
                mount_point=self.mount_point
            )
            return response['data']['data']
        except Exception as e:
            logger.error(f"Failed to get secret from {path}: {e}")
            return None

    async def set_secret(self, path: str, secret: dict) -> bool:
        """Set secret in Vault."""
        try:
            await asyncio.to_thread(
                self.client.secrets.kv.v2.create_or_update_secret,
                path=path,
                secret=secret,
                mount_point=self.mount_point
            )
            logger.info(f"Set secret at {path}")
            return True
        except Exception as e:
            logger.error(f"Failed to set secret: {e}")
            return False

    async def delete_secret(self, path: str) -> bool:
        """Delete secret from Vault."""
        try:
            await asyncio.to_thread(
                self.client.secrets.kv.v2.delete_metadata_and_all_versions,
                path=path,
                mount_point=self.mount_point
            )
            logger.info(f"Deleted secret at {path}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete secret: {e}")
            return False

    async def shutdown(self) -> None:
        """Cleanup Vault connection."""
        logger.info("VaultSecretProvider shutdown")
```

### Step 5: Unified Config Manager

Create `src/config/unified_manager.py`:

```python
"""
Unified configuration manager that combines config and secret providers.
"""

import os
import logging
from typing import Optional, Dict, Any
from cachetools import TTLCache

from .providers.base import ConfigProvider, SecretProvider
from .providers.file_provider import FileConfigProvider, EnvSecretProvider
from .providers.etcd_provider import EtcdConfigProvider
from .providers.vault_provider import VaultSecretProvider

logger = logging.getLogger(__name__)


class UnifiedConfigManager:
    """
    Unified configuration manager supporting multiple backends.

    Automatically selects backend based on environment variables:
    - CONFIG_BACKEND: file | etcd
    - SECRETS_BACKEND: env | vault
    """

    def __init__(
        self,
        config_provider: ConfigProvider,
        secret_provider: SecretProvider,
        cache_ttl: int = 300
    ):
        self.config_provider = config_provider
        self.secret_provider = secret_provider

        # Cache for merged configs (config + secrets)
        self._cache = TTLCache(maxsize=10000, ttl=cache_ttl)

    @classmethod
    async def from_env(cls) -> 'UnifiedConfigManager':
        """
        Create UnifiedConfigManager from environment variables.

        Environment variables:
        - CONFIG_BACKEND: file | etcd (default: file)
        - SECRETS_BACKEND: env | vault (default: env)

        For file backend:
        - WEBHOOKS_CONFIG_FILE: path to webhooks.json

        For etcd backend:
        - ETCD_HOST: etcd hostname
        - ETCD_PORT: etcd port (default: 2379)

        For vault backend:
        - VAULT_ADDR: Vault address
        - VAULT_ROLE_ID: AppRole role ID
        - VAULT_SECRET_ID: AppRole secret ID
        """
        config_backend = os.getenv('CONFIG_BACKEND', 'file').lower()
        secrets_backend = os.getenv('SECRETS_BACKEND', 'env').lower()

        # Create config provider
        if config_backend == 'etcd':
            config_provider = EtcdConfigProvider(
                host=os.getenv('ETCD_HOST', 'localhost'),
                port=int(os.getenv('ETCD_PORT', '2379'))
            )
        else:  # file
            config_provider = FileConfigProvider(
                config_file=os.getenv('WEBHOOKS_CONFIG_FILE', 'webhooks.json')
            )

        # Create secret provider
        if secrets_backend == 'vault':
            vault_addr = os.getenv('VAULT_ADDR')
            role_id = os.getenv('VAULT_ROLE_ID')
            secret_id = os.getenv('VAULT_SECRET_ID')

            if not vault_addr or not role_id or not secret_id:
                raise ValueError(
                    "VAULT_ADDR, VAULT_ROLE_ID, and VAULT_SECRET_ID required "
                    "when SECRETS_BACKEND=vault"
                )

            secret_provider = VaultSecretProvider(
                vault_addr=vault_addr,
                role_id=role_id,
                secret_id=secret_id
            )
        else:  # env
            secret_provider = EnvSecretProvider()

        # Initialize providers
        await config_provider.initialize()
        await secret_provider.initialize()

        logger.info(
            f"UnifiedConfigManager created "
            f"(config={config_backend}, secrets={secrets_backend})"
        )

        return cls(config_provider, secret_provider)

    async def get_webhook_config(
        self,
        webhook_id: str,
        include_secrets: bool = True
    ) -> Optional[Dict[str, Any]]:
        """
        Get complete webhook configuration (config + secrets merged).

        Args:
            webhook_id: Webhook identifier
            include_secrets: Whether to include secrets (default: True)

        Returns:
            Merged config dict or None
        """
        # Check cache
        cache_key = f"{webhook_id}:{include_secrets}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        # Get config
        config = await self.config_provider.get_config(webhook_id)
        if not config:
            return None

        # Merge with secrets if requested
        if include_secrets:
            secret_path = f"webhooks/{webhook_id}/secrets"
            secrets = await self.secret_provider.get_secret(secret_path)

            if secrets:
                # Merge secrets into config
                if 'bearer-token' in secrets:
                    config['authorization'] = f"Bearer {secrets['bearer-token']}"

                if 'hmac-secret' in secrets:
                    config['hmac'] = {
                        'secret': secrets['hmac-secret'],
                        'header': secrets.get('hmac-header', 'X-Signature'),
                        'algorithm': secrets.get('hmac-algorithm', 'sha256')
                    }

                if 'channel-token' in secrets and 'module-config' in config:
                    config['module-config']['channel_token'] = secrets['channel-token']

        # Cache result
        self._cache[cache_key] = config

        return config

    async def create_webhook_config(
        self,
        webhook_id: str,
        config: Dict[str, Any],
        secrets: Optional[Dict[str, str]] = None,
        ttl: Optional[int] = None
    ) -> bool:
        """
        Create webhook configuration and secrets.

        Args:
            webhook_id: Webhook identifier
            config: Configuration dict (non-sensitive)
            secrets: Secrets dict (sensitive)
            ttl: Optional TTL in seconds

        Returns:
            True if created successfully
        """
        # Create config
        config_success = await self.config_provider.set_config(
            webhook_id,
            config,
            ttl=ttl
        )

        if not config_success:
            return False

        # Create secrets if provided
        if secrets:
            secret_path = f"webhooks/{webhook_id}/secrets"
            secret_success = await self.secret_provider.set_secret(
                secret_path,
                secrets
            )

            if not secret_success:
                logger.warning(f"Failed to create secrets for {webhook_id}")
                # Don't fail entirely, config was created

        # Invalidate cache
        self._invalidate_cache(webhook_id)

        return True

    async def update_webhook_config(
        self,
        webhook_id: str,
        config: Dict[str, Any]
    ) -> bool:
        """Update webhook configuration."""
        success = await self.config_provider.set_config(webhook_id, config)

        if success:
            self._invalidate_cache(webhook_id)

        return success

    async def delete_webhook_config(
        self,
        webhook_id: str,
        delete_secrets: bool = True
    ) -> bool:
        """
        Delete webhook configuration and optionally secrets.

        Args:
            webhook_id: Webhook identifier
            delete_secrets: Whether to delete secrets (default: True)

        Returns:
            True if deleted successfully
        """
        # Delete config
        config_success = await self.config_provider.delete_config(webhook_id)

        # Delete secrets if requested
        if delete_secrets:
            secret_path = f"webhooks/{webhook_id}/secrets"
            await self.secret_provider.delete_secret(secret_path)

        # Invalidate cache
        self._invalidate_cache(webhook_id)

        return config_success

    async def list_webhook_ids(self, prefix: str = "") -> list[str]:
        """List all webhook IDs."""
        return await self.config_provider.list_keys(prefix)

    def _invalidate_cache(self, webhook_id: str):
        """Invalidate cache entries for webhook."""
        keys_to_remove = [
            f"{webhook_id}:True",
            f"{webhook_id}:False"
        ]
        for key in keys_to_remove:
            self._cache.pop(key, None)

    async def watch_config_changes(self, callback):
        """Watch for configuration changes."""
        async def _wrapped_callback(change_type, key, config):
            # Invalidate cache
            self._invalidate_cache(key)
            # Call original callback
            await callback(change_type, key, config)

        await self.config_provider.watch_changes("", _wrapped_callback)

    async def shutdown(self):
        """Shutdown all providers."""
        await self.config_provider.shutdown()
        await self.secret_provider.shutdown()
        logger.info("UnifiedConfigManager shutdown")


# Global instance
_unified_manager: Optional[UnifiedConfigManager] = None


async def get_config_manager() -> UnifiedConfigManager:
    """Get singleton config manager."""
    global _unified_manager
    if _unified_manager is None:
        _unified_manager = await UnifiedConfigManager.from_env()
    return _unified_manager
```

### Step 6: Integration with FastAPI

Update `src/main.py`:

```python
from src.config.unified_manager import get_config_manager

@app.on_event("startup")
async def startup():
    """Initialize application."""
    # Initialize unified config manager (auto-selects backend from env)
    config_mgr = await get_config_manager()

    # Register for config change notifications
    await config_mgr.watch_config_changes(on_config_change)

    logger.info("Application started")


async def on_config_change(change_type: str, webhook_id: str, config: dict):
    """Handle configuration changes."""
    logger.info(f"Config {change_type}: {webhook_id}")
    # Invalidate caches, reload modules, etc.


@app.post("/webhook/{webhook_id}")
async def receive_webhook(webhook_id: str, request: Request):
    """Receive webhook using unified config manager."""
    config_mgr = await get_config_manager()

    # Get config (works with ANY backend!)
    config = await config_mgr.get_webhook_config(webhook_id)

    if not config:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # ... process webhook as normal ...
```

---

## Usage Examples

### Development (JSON + Env)

```bash
# .env
CONFIG_BACKEND=file
SECRETS_BACKEND=env
WEBHOOKS_CONFIG_FILE=webhooks.json

# Secrets as env vars
WEBHOOK_WH_ABC123_TOKEN=xyz123...
WEBHOOK_WH_ABC123_CHANNEL_TOKEN=abc456...
```

```json
// webhooks.json
{
  "wh_abc123": {
    "data_type": "json",
    "module": "webhook_connect",
    "module-config": {
      "channel": "ch_abc123",
      "max_queue_size": 10000
    }
  }
}
```

### Staging (etcd)

```bash
# .env
CONFIG_BACKEND=etcd
SECRETS_BACKEND=env
ETCD_HOST=etcd.staging.local

# Secrets still in env vars (for simplicity)
WEBHOOK_WH_ABC123_TOKEN=xyz123...
```

```bash
# Store config in etcd
etcdctl put /webhooks/configs/wh_abc123 '{
  "data_type": "json",
  "module": "webhook_connect",
  "module-config": {...}
}'
```

### Production (etcd + Vault)

```bash
# .env
CONFIG_BACKEND=etcd
SECRETS_BACKEND=vault
ETCD_HOST=etcd1,etcd2,etcd3
VAULT_ADDR=https://vault.prod.local
VAULT_ROLE_ID=...
VAULT_SECRET_ID=...
```

```bash
# Config in etcd
etcdctl put /webhooks/configs/wh_abc123 '{...}'

# Secrets in Vault
vault kv put webhooks/wh_abc123/secrets \
  bearer-token=xyz123... \
  channel-token=abc456... \
  hmac-secret=def789...
```

---

## Deployment Scenarios

### Scenario 1: Local Development

```yaml
# docker-compose.dev.yml
services:
  webhook-receiver:
    environment:
      - CONFIG_BACKEND=file
      - SECRETS_BACKEND=env
      - WEBHOOK_WH_TEST_TOKEN=dev_token_123
    volumes:
      - ./webhooks.json:/app/webhooks.json
```

**Pros**: Simple, fast iteration
**Cons**: Not production-ready

### Scenario 2: Staging (etcd)

```yaml
# docker-compose.staging.yml
services:
  etcd:
    image: bitnami/etcd:latest

  webhook-receiver:
    environment:
      - CONFIG_BACKEND=etcd
      - SECRETS_BACKEND=env
      - ETCD_HOST=etcd
```

**Pros**: Tests distributed config, still simple secrets
**Cons**: Secrets in env vars not ideal

### Scenario 3: Production (etcd + Vault)

```yaml
# docker-compose.prod.yml
services:
  etcd1:
    image: bitnami/etcd:latest
  etcd2:
    image: bitnami/etcd:latest
  etcd3:
    image: bitnami/etcd:latest

  vault:
    image: vault:latest

  webhook-receiver:
    environment:
      - CONFIG_BACKEND=etcd
      - SECRETS_BACKEND=vault
      - ETCD_HOST=etcd1,etcd2,etcd3
      - VAULT_ADDR=https://vault:8200
```

**Pros**: Production-grade security and availability
**Cons**: More complex to operate

---

## Migration Path

### Phase 1: Start with Files

```bash
# Development
CONFIG_BACKEND=file
SECRETS_BACKEND=env
```

Deploy with JSON files, iterate quickly.

### Phase 2: Add etcd for Config

```bash
# Staging
CONFIG_BACKEND=etcd  # ← Changed
SECRETS_BACKEND=env

# Run migration script
./migrate_json_to_etcd.py
```

Test multi-instance deployment with real-time config sync.

### Phase 3: Add Vault for Secrets

```bash
# Production
CONFIG_BACKEND=etcd
SECRETS_BACKEND=vault  # ← Changed

# Run migration script
./migrate_env_to_vault.py
```

Move secrets to Vault, enable rotation.

### Phase 4: Full Production

```bash
CONFIG_BACKEND=etcd
SECRETS_BACKEND=vault

# Both backends in production
# etcd: 3-node cluster
# Vault: 3-node cluster with auto-unseal
```

---

## Comparison Matrix

| Deployment | Config Backend | Secret Backend | Setup Time | Monthly Cost | Security | Best For |
|------------|----------------|----------------|------------|--------------|----------|----------|
| **Dev** | File | Env | 5 min | $0 | ⚠️ Low | Local development |
| **Small** | File | Env | 10 min | $0 | ⚠️ Low | < 10 webhooks, single instance |
| **Staging** | etcd | Env | 30 min | $30 | ⚠️ Medium | Testing, < 100 webhooks |
| **Production** | etcd | Vault | 2 hours | $85 | ✅ High | Production, 100+ webhooks |
| **Enterprise** | etcd (HA) | Vault (HA) | 1 day | $200 | ✅ Very High | Compliance, 1000+ webhooks |

---

## Benefits of Unified System

### 1. **Single Codebase**

```python
# Same code works everywhere!
config = await config_mgr.get_webhook_config("wh_abc123")

# Dev: Reads from webhooks.json
# Staging: Reads from etcd
# Prod: Reads from etcd + Vault
```

### 2. **Gradual Migration**

Start simple, add complexity as you grow:
- Day 1: JSON files
- Month 1: etcd
- Month 3: Vault

### 3. **Environment Parity**

Dev, staging, and production use the same code, just different backends.

### 4. **Testing Flexibility**

```python
# Unit tests: Use file backend
os.environ['CONFIG_BACKEND'] = 'file'

# Integration tests: Use real etcd
os.environ['CONFIG_BACKEND'] = 'etcd'
```

### 5. **Cost Optimization**

Pay for what you need:
- Free for development
- $30/month for staging
- $85/month for production

---

## Summary

**Unified Config System enables**:

✅ **Multiple backends** - File, etcd, Vault
✅ **Runtime selection** - Environment-driven
✅ **Same codebase** - No code changes between envs
✅ **Gradual migration** - Start simple, add complexity
✅ **Flexible deployment** - Dev to enterprise

**Perfect for your Portal Project**:
- Start with JSON files for rapid prototyping
- Add etcd when deploying multiple products
- Add Vault when launching production SaaS
- All using the same code!

Ready to implement! 🚀
