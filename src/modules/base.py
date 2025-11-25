from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseModule(ABC):
    """Base class for all webhook processing modules."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the module with configuration.
        
        Args:
            config: The webhook configuration including connection details
        """
        self.config = config
        self.connection_details = config.get('connection_details', {})
        self.module_config = config.get('module-config', {})
    
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
