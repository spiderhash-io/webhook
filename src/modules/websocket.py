import json
from typing import Any, Dict
import websockets
from src.modules.base import BaseModule


class WebSocketModule(BaseModule):
    """Module for forwarding webhook payloads to WebSocket connections."""
    
    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        """Forward payload to WebSocket server."""
        ws_url = self.module_config.get('url')
        
        if not ws_url:
            raise Exception("WebSocket URL not specified in module-config")
        
        # Prepare message
        message_format = self.module_config.get('format', 'json')
        include_headers = self.module_config.get('include_headers', False)
        
        if message_format == 'json':
            message_data = {
                'payload': payload
            }
            if include_headers:
                message_data['headers'] = dict(headers)
            
            message = json.dumps(message_data)
        else:
            # Send raw payload
            if isinstance(payload, (dict, list)):
                message = json.dumps(payload)
            else:
                message = str(payload)
        
        # Connection settings
        timeout = self.module_config.get('timeout', 10)
        max_retries = self.module_config.get('max_retries', 3)
        
        # Custom headers for WebSocket connection
        extra_headers = self.module_config.get('headers', {})
        
        # Attempt to send with retries
        for attempt in range(max_retries):
            try:
                async with websockets.connect(
                    ws_url,
                    extra_headers=extra_headers,
                    open_timeout=timeout,
                    close_timeout=timeout
                ) as websocket:
                    await websocket.send(message)
                    
                    # Optionally wait for response
                    if self.module_config.get('wait_for_response', False):
                        response = await websocket.recv()
                        print(f"WebSocket response: {response}")
                    
                    print(f"Webhook forwarded to WebSocket: {ws_url}")
                    return  # Success, exit
                    
            except websockets.exceptions.WebSocketException as e:
                print(f"WebSocket error (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt == max_retries - 1:
                    raise Exception(f"Failed to send to WebSocket after {max_retries} attempts: {e}")
            except Exception as e:
                print(f"Failed to send to WebSocket: {e}")
                raise e
