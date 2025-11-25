from typing import Any, Dict
from src.modules.base import BaseModule


class LogModule(BaseModule):
    """Module for logging webhook payloads to stdout."""
    
    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        """Print payload and headers to stdout."""
        print("config: " + str(self.config))
        print("headers: " + str(headers))
        print("body: " + str(payload))
