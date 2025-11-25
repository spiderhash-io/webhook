import httpx
from typing import Any, Dict
from src.modules.base import BaseModule


class HTTPWebhookModule(BaseModule):
    """Module for forwarding webhook payloads to another HTTP endpoint."""
    
    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        """Forward payload to configured HTTP endpoint."""
        url = self.module_config.get('url')
        method = self.module_config.get('method', 'POST').upper()
        forward_headers = self.module_config.get('forward_headers', True)
        timeout = self.module_config.get('timeout', 30)
        
        if not url:
            raise Exception("URL not specified in module-config")
        
        # Prepare headers
        request_headers = {}
        if forward_headers:
            # Filter out hop-by-hop headers
            skip_headers = {'host', 'connection', 'keep-alive', 'transfer-encoding'}
            request_headers = {k: v for k, v in headers.items() if k.lower() not in skip_headers}
        
        # Add custom headers from config
        custom_headers = self.module_config.get('headers', {})
        request_headers.update(custom_headers)
        
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                if method == 'POST':
                    response = await client.post(url, json=payload, headers=request_headers)
                elif method == 'PUT':
                    response = await client.put(url, json=payload, headers=request_headers)
                elif method == 'PATCH':
                    response = await client.patch(url, json=payload, headers=request_headers)
                else:
                    raise Exception(f"Unsupported HTTP method: {method}")
                
                response.raise_for_status()
                print(f"HTTP webhook forwarded to {url}: {response.status_code}")
                
        except httpx.HTTPError as e:
            print(f"Failed to forward HTTP webhook to {url}: {e}")
            raise e
