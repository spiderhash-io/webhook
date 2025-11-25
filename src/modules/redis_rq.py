from typing import Any, Dict
from rq import Queue
from src.modules.base import BaseModule


class RedisRQModule(BaseModule):
    """Module for queuing webhook payloads to Redis RQ."""
    
    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        """Queue payload processing using Redis RQ."""
        connection = self.connection_details.get('conn')
        
        if not connection:
            raise Exception("Redis connection is not defined")
        
        queue_name = self.module_config.get('queue_name', 'default')
        function_name = self.module_config.get('function')
        
        if not function_name:
            raise Exception("Function name not specified in module-config")
        
        # Create queue
        q = Queue(queue_name, connection=connection)
        
        # Enqueue the task
        # Note: The function should be importable and accept payload as argument
        result = q.enqueue(function_name, payload, headers)
        
        print(f"Task queued to Redis RQ: {result.id}")
