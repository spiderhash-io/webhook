import uuid
import os
from typing import Any, Dict
from src.modules.base import BaseModule


class SaveToDiskModule(BaseModule):
    """Module for saving webhook payloads to disk."""
    
    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        """Save payload to disk as a text file."""
        my_uuid = uuid.uuid4()
        
        path = self.module_config.get('path', '.')
        
        if path != '.' and not os.path.exists(path):
            os.makedirs(path)

        file_path = os.path.join(path, f"{my_uuid}.txt")
        with open(file_path, mode="w") as f:
            f.write(str(payload))    
            f.flush()
            f.close()
