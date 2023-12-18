import json
import asyncio

from fastapi import HTTPException, Request
from src.utils import print_to_stdout
from src.modules.rabbitmq import rabbitmq_publish


class WebhookHandler:
    def __init__(self, webhook_id, configs, connection_config, request: Request):
        self.webhook_id = webhook_id
        self.config = configs.get(webhook_id)
        if not self.config:
            raise HTTPException(status_code=404, detail="Webhook ID not found")
        self.connection_config = connection_config
        self.request = request
        self.headers = self.request.headers

    async def validate_webhook(self):

        expected_auth = self.config.get("authorization", {})

        if expected_auth:
            authorization_header = self.request.headers.get('Authorization')
            if "Bearer" in expected_auth and not authorization_header.startswith("Bearer"):
                return False, "Unauthorized: Bearer token required"

            if authorization_header != expected_auth:
                return False, "Unauthorized"

        return True, "Valid webhook"

    async def process_webhook(self):

        # Read the incoming data based on its type
        if self.config['data_type'] == 'json':
            try:
                payload = await self.request.json()
            except json.JSONDecodeError:
                raise HTTPException(status_code=400, detail="Malformed JSON payload")
        elif self.config['data_type'] == 'blob':
            payload = await self.request.body()
            # Additional blob handling...
        else:
            raise HTTPException(status_code=415, detail="Unsupported data type")

        # Execute the relevant module function
        if self.config['module'] == 'log':
            asyncio.create_task(print_to_stdout(payload, self.headers, self.config))
        elif self.config['module'] == 'rabbitmq':
            asyncio.create_task(rabbitmq_publish(payload, self.config, self.headers))
        else:
            return HTTPException(status_code=501, detail="Unsupported module")
