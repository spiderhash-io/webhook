"""
etcd-based configuration provider.

Stores webhook and connection configurations in an etcd cluster.
Supports namespaces for organizational grouping, real-time watch for
incremental cache updates, and automatic reconnection with backoff.

Key layout in etcd:
    /cwm/{namespace}/webhooks/{webhook_id}   → webhook config JSON
    /cwm/global/connections/{conn_name}      → connection config JSON

Users manage etcd directly (etcdctl put/delete). This provider is read-only.
"""

import json
import logging
import random
import re
import threading
import time
from typing import Any, Callable, Coroutine, Dict, List, Optional

from src.config_provider import ConfigChangeCallback, ConfigProvider
from src.utils import sanitize_error_message

logger = logging.getLogger(__name__)

# Namespace validation: alphanumeric, hyphens, underscores, 1-64 chars
NAMESPACE_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")

# Max reconnect delay in seconds
MAX_RECONNECT_DELAY = 60.0
INITIAL_RECONNECT_DELAY = 1.0


def _validate_namespace(namespace: str) -> bool:
    """Validate a namespace string."""
    return bool(NAMESPACE_PATTERN.match(namespace))


class EtcdConfigProvider(ConfigProvider):
    """
    etcd-backed configuration provider with in-memory cache.

    Features:
    - Loads all config at startup via get_prefix
    - Watches for real-time incremental updates (one key per event)
    - Reconnects automatically with exponential backoff + jitter
    - Cache continues serving reads when etcd is unavailable
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 2379,
        prefix: str = "/cwm/",
        namespace: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ):
        """
        Initialize etcd config provider.

        Args:
            host: etcd server hostname.
            port: etcd server port.
            prefix: Key prefix in etcd (default: /cwm/).
            namespace: Default namespace for webhook lookups.
            username: Optional etcd username for authentication.
            password: Optional etcd password for authentication.
        """
        if not isinstance(host, str) or not host:
            raise ValueError("host must be a non-empty string")
        if not isinstance(port, int) or port < 1 or port > 65535:
            raise ValueError("port must be an integer between 1 and 65535")
        if not isinstance(prefix, str) or not prefix:
            raise ValueError("prefix must be a non-empty string")
        if namespace is not None and not _validate_namespace(namespace):
            raise ValueError(
                f"Invalid namespace: {namespace!r}. "
                "Must be 1-64 chars of [a-zA-Z0-9_-]"
            )

        self._host = host
        self._port = port
        self._prefix = prefix.rstrip("/") + "/"
        self._default_namespace = namespace or "default"
        self._username = username
        self._password = password

        # In-memory cache: {namespace: {webhook_id: config_dict}}
        self._cache: Dict[str, Dict[str, Any]] = {}
        # Connection cache: {conn_name: config_dict}
        self._connections_cache: Dict[str, Any] = {}
        # Protects _cache and _connections_cache from concurrent read/write
        self._cache_lock = threading.Lock()

        self._client = None
        self._watch_id = None
        self._watch_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._initialized = False
        self._connected = False
        self._change_callbacks: List[ConfigChangeCallback] = []
        self._loop = None  # asyncio event loop for callbacks

    def _create_client(self):
        """Create an etcd3 client instance."""
        import etcd3

        kwargs = {
            "host": self._host,
            "port": self._port,
        }
        if self._username and self._password:
            kwargs["user"] = self._username
            kwargs["password"] = self._password

        return etcd3.client(**kwargs)

    async def initialize(self) -> None:
        """
        Initialize the provider: connect to etcd, load all keys, start watch.

        Raises:
            Exception: If initial connection to etcd fails.
        """
        import asyncio

        self._loop = asyncio.get_running_loop()

        # Create client and load initial data in thread (etcd3 is sync)
        await asyncio.get_running_loop().run_in_executor(
            None, self._sync_initialize
        )

        self._initialized = True
        logger.info(
            "EtcdConfigProvider initialized: %d namespace(s), %d connection(s)",
            len(self._cache),
            len(self._connections_cache),
        )

    def _sync_initialize(self) -> None:
        """Synchronous initialization (runs in executor thread)."""
        self._client = self._create_client()
        self._connected = True

        # Load all keys under prefix
        self._full_reload()

        # Start watch thread
        self._start_watch()

    def _full_reload(self) -> None:
        """Load all keys under the prefix into cache (RCU swap)."""
        if not self._client:
            return

        # Build new caches locally to avoid holding lock during network I/O
        new_cache: Dict[str, Dict[str, Any]] = {}
        new_connections: Dict[str, Any] = {}

        try:
            results = self._client.get_prefix(self._prefix)
            for value, metadata in results:
                if value is None or metadata is None:
                    continue
                key = metadata.key.decode("utf-8")
                self._apply_put(key, value, new_cache, new_connections)
        except Exception as e:
            sanitized = sanitize_error_message(e, "EtcdConfigProvider._full_reload")
            logger.error("Failed to load from etcd: %s", sanitized)
            raise

        # Atomic swap under lock
        with self._cache_lock:
            self._cache = new_cache
            self._connections_cache = new_connections

    def _apply_put(
        self,
        key: str,
        value: bytes,
        cache: Dict[str, Dict[str, Any]],
        connections: Dict[str, Any],
    ) -> None:
        """
        Parse a key/value pair and store into the provided dicts.

        This helper is lock-free; callers are responsible for synchronization.

        Args:
            key: The full etcd key (e.g., /cwm/ns1/webhooks/hook1).
            value: The raw bytes value.
            cache: Target webhook cache dict.
            connections: Target connections cache dict.
        """
        relative = key[len(self._prefix):]
        parts = relative.split("/")

        try:
            config = json.loads(value.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.warning("Invalid JSON at key %s: %s", key, e)
            return

        if not isinstance(config, dict):
            logger.warning("Non-dict value at key %s, skipping", key)
            return

        # Route: {namespace}/webhooks/{webhook_id}
        if len(parts) == 3 and parts[1] == "webhooks":
            namespace = parts[0]
            webhook_id = parts[2]
            if not _validate_namespace(namespace):
                logger.warning("Invalid namespace in key %s", key)
                return
            if namespace not in cache:
                cache[namespace] = {}
            cache[namespace][webhook_id] = config

        # Route: global/connections/{conn_name}
        elif len(parts) == 3 and parts[0] == "global" and parts[1] == "connections":
            conn_name = parts[2]
            connections[conn_name] = config

        else:
            logger.debug("Ignoring unrecognized key: %s", key)

    def _process_put_event(self, key: str, value: bytes) -> None:
        """Process a PUT event by updating the in-memory cache (thread-safe)."""
        with self._cache_lock:
            self._apply_put(key, value, self._cache, self._connections_cache)

    def _process_delete_event(self, key: str) -> None:
        """
        Process a DELETE event by removing from cache (thread-safe).

        Args:
            key: The full etcd key.
        """
        relative = key[len(self._prefix):]
        parts = relative.split("/")

        with self._cache_lock:
            # Route: {namespace}/webhooks/{webhook_id}
            if len(parts) == 3 and parts[1] == "webhooks":
                namespace = parts[0]
                webhook_id = parts[2]
                if namespace in self._cache:
                    self._cache[namespace].pop(webhook_id, None)
                    # Clean up empty namespace
                    if not self._cache[namespace]:
                        del self._cache[namespace]

            # Route: global/connections/{conn_name}
            elif len(parts) == 3 and parts[0] == "global" and parts[1] == "connections":
                conn_name = parts[2]
                self._connections_cache.pop(conn_name, None)

    def _start_watch(self) -> None:
        """Start the background watch thread."""
        if self._watch_thread and self._watch_thread.is_alive():
            return

        self._stop_event.clear()
        self._watch_thread = threading.Thread(
            target=self._watch_loop, daemon=True, name="etcd-watch"
        )
        self._watch_thread.start()

    def _watch_loop(self) -> None:
        """
        Background thread that watches etcd for changes.

        Reconnects with exponential backoff + jitter on failures.
        """
        delay = INITIAL_RECONNECT_DELAY

        while not self._stop_event.is_set():
            try:
                self._connected = True
                events_iterator, cancel = self._client.watch_prefix(self._prefix)
                self._watch_id = cancel

                for event in events_iterator:
                    if self._stop_event.is_set():
                        break

                    key = event.key.decode("utf-8")

                    # Import event types lazily
                    import etcd3.events as etcd_events

                    if isinstance(event, etcd_events.PutEvent):
                        self._process_put_event(key, event.value)
                        self._notify_change("put", key, event.value)
                    elif isinstance(event, etcd_events.DeleteEvent):
                        self._process_delete_event(key)
                        self._notify_change("delete", key, None)

                    # Reset backoff on successful event
                    delay = INITIAL_RECONNECT_DELAY

            except Exception as e:
                if self._stop_event.is_set():
                    break

                self._connected = False
                sanitized = sanitize_error_message(
                    e, "EtcdConfigProvider._watch_loop"
                )
                logger.warning("etcd watch error: %s. Reconnecting in %.1fs", sanitized, delay)

                # Wait with backoff
                self._stop_event.wait(timeout=delay)
                if self._stop_event.is_set():
                    break

                # Exponential backoff with jitter
                delay = min(delay * 2, MAX_RECONNECT_DELAY)
                delay += random.uniform(0, delay * 0.1)  # 10% jitter

                # Reconnect and full reload to catch missed events
                try:
                    self._client = self._create_client()
                    self._full_reload()
                    self._connected = True
                    logger.info("Reconnected to etcd, cache reloaded")
                except Exception as reconnect_err:
                    sanitized = sanitize_error_message(
                        reconnect_err, "EtcdConfigProvider.reconnect"
                    )
                    logger.error("Failed to reconnect to etcd: %s", sanitized)

    def _notify_change(
        self, event_type: str, key: str, value: Optional[bytes]
    ) -> None:
        """Notify registered callbacks of a config change."""
        if not self._change_callbacks or not self._loop:
            return

        try:
            config = None
            if value is not None:
                try:
                    config = json.loads(value.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass

            for callback in self._change_callbacks:
                self._loop.call_soon_threadsafe(
                    lambda cb=callback, et=event_type, k=key, c=config: (
                        self._loop.create_task(cb(et, k, c))
                    )
                )
        except Exception as e:
            logger.debug("Error notifying change callback: %s", e)

    async def shutdown(self) -> None:
        """Stop the watch thread and close the etcd connection."""
        self._stop_event.set()
        self._initialized = False

        if self._watch_id:
            try:
                self._watch_id()  # cancel is a callable
            except Exception:
                pass
            self._watch_id = None

        if self._watch_thread and self._watch_thread.is_alive():
            self._watch_thread.join(timeout=5.0)

        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

        self._connected = False
        logger.info("EtcdConfigProvider shut down")

    def get_webhook_config(
        self, webhook_id: str, namespace: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Get a webhook's configuration from the in-memory cache.

        Args:
            webhook_id: The webhook identifier.
            namespace: Namespace to look in (defaults to configured default).

        Returns:
            Webhook config dict, or None if not found.
        """
        ns = namespace or self._default_namespace
        with self._cache_lock:
            return self._cache.get(ns, {}).get(webhook_id)

    def get_all_webhook_configs(
        self, namespace: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get all webhook configurations for a namespace.

        Args:
            namespace: Namespace to look in (defaults to configured default).

        Returns:
            Dict mapping webhook_id -> config dict.
        """
        ns = namespace or self._default_namespace
        with self._cache_lock:
            return dict(self._cache.get(ns, {}))

    def get_connection_config(self, conn_name: str) -> Optional[Dict[str, Any]]:
        """Get a connection config (always global)."""
        with self._cache_lock:
            return self._connections_cache.get(conn_name)

    def get_all_connection_configs(self) -> Dict[str, Any]:
        """Get all connection configs (always global)."""
        with self._cache_lock:
            return dict(self._connections_cache)

    def get_status(self) -> Dict[str, Any]:
        """Get etcd provider status information."""
        with self._cache_lock:
            total_webhooks = sum(len(ns) for ns in self._cache.values())
            namespaces_count = len(self._cache)
            namespaces = list(self._cache.keys())
            connections_count = len(self._connections_cache)
        return {
            "backend": "etcd",
            "initialized": self._initialized,
            "connected": self._connected,
            "host": self._host,
            "port": self._port,
            "prefix": self._prefix,
            "default_namespace": self._default_namespace,
            "namespaces_count": namespaces_count,
            "namespaces": namespaces,
            "total_webhooks": total_webhooks,
            "connections_count": connections_count,
        }

    def get_namespaces(self) -> List[str]:
        """Get list of all known namespaces."""
        with self._cache_lock:
            return list(self._cache.keys())

    def on_config_change(self, callback: ConfigChangeCallback) -> None:
        """Register a callback for config change notifications."""
        self._change_callbacks.append(callback)
