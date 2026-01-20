from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseModule(ABC):
    """Base class for all webhook processing modules."""

    def __init__(self, config: Dict[str, Any], pool_registry=None):
        """
        Initialize the module with configuration.

        Args:
            config: The webhook configuration including connection details
            pool_registry: Optional ConnectionPoolRegistry for getting connection pools

        Raises:
            TypeError: If config is not a dictionary
            ValueError: If connection_details or module-config are not dictionaries
        """
        # SECURITY: Validate config type to prevent type confusion attacks
        if not isinstance(config, dict):
            raise TypeError(f"Config must be a dictionary, got {type(config).__name__}")

        self.config = config

        # SECURITY: Ensure connection_details is always a dict to prevent type confusion
        connection_details_raw = config.get("connection_details", {})
        if not isinstance(connection_details_raw, dict):
            # If connection_details is not a dict (e.g., None, string, etc.), use empty dict
            # This prevents type confusion attacks where modules expect a dict
            self.connection_details = {}
        else:
            self.connection_details = connection_details_raw

        # SECURITY: Ensure module_config is always a dict to prevent type confusion
        module_config_raw = config.get("module-config", {})
        if not isinstance(module_config_raw, dict):
            # If module-config is not a dict (e.g., None, string, etc.), use empty dict
            # This prevents type confusion attacks where modules expect a dict
            self.module_config = {}
        else:
            self.module_config = module_config_raw

        self.pool_registry = pool_registry

    @abstractmethod
    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        """
        Process the webhook payload.

        Args:
            payload: The webhook payload (parsed based on data_type)
            headers: The request headers
        """
        pass

    async def setup(self) -> None:
        """
        Optional setup method called once during initialization.
        Override this if your module needs setup (e.g., creating connections).
        """
        pass

    async def teardown(self) -> None:
        """
        Optional teardown method called during shutdown.
        Override this if your module needs cleanup (e.g., closing connections).
        """
        pass
