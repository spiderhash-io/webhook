import json
import asyncio

from fastapi import HTTPException, Request
from src.modules.registry import ModuleRegistry
from src.validators import AuthorizationValidator, BasicAuthValidator, HMACValidator, IPWhitelistValidator, JWTValidator, RateLimitValidator, JsonSchemaValidator, RecaptchaValidator
from src.input_validator import InputValidator
from src.retry_handler import retry_handler


class WebhookHandler:
    def __init__(self, webhook_id, configs, connection_config, request: Request):
        self.webhook_id = webhook_id
        self.config = configs.get(webhook_id)
        if not self.config:
            raise HTTPException(status_code=404, detail="Webhook ID not found")
        self.connection_config = connection_config
        self.request = request
        self.headers = self.request.headers
        
        # Initialize validators
        self.validators = [
            RateLimitValidator(self.config, webhook_id),  # Check rate limit first
            RecaptchaValidator(self.config),  # Google reCAPTCHA validation
            BasicAuthValidator(self.config),  # Basic auth
            JWTValidator(self.config),  # JWT auth
            AuthorizationValidator(self.config),  # Bearer token (simple)
            HMACValidator(self.config),  # HMAC signature
            IPWhitelistValidator(self.config),  # IP whitelist
            JsonSchemaValidator(self.config),  # JSON Schema validation
        ]

    async def validate_webhook(self):
        """Validate webhook using all configured validators."""
        # Get raw body for HMAC validation
        body = await self.request.body()
        
        # Convert headers to dict
        headers_dict = {k.lower(): v for k, v in self.request.headers.items()}
        
        # Run all validators
        for validator in self.validators:
            is_valid, message = await validator.validate(headers_dict, body)
            if not is_valid:
                return False, message
        
        return True, "Valid webhook"

    async def process_webhook(self):
        """Process webhook payload using the configured module."""
        # Validate webhook ID format
        is_valid, msg = InputValidator.validate_webhook_id(self.webhook_id)
        if not is_valid:
            raise HTTPException(status_code=400, detail=msg)
        
        # Get raw body for validation
        body = await self.request.body()
        
        # Validate headers
        headers_dict = {k: v for k, v in self.request.headers.items()}
        is_valid, msg = InputValidator.validate_headers(headers_dict)
        if not is_valid:
            raise HTTPException(status_code=400, detail=msg)
        
        # Validate payload size
        is_valid, msg = InputValidator.validate_payload_size(body)
        if not is_valid:
            raise HTTPException(status_code=413, detail=msg)
        
        # Read the incoming data based on its type
        if self.config['data_type'] == 'json':
            try:
                payload = json.loads(body.decode('utf-8'))
            except json.JSONDecodeError:
                raise HTTPException(status_code=400, detail="Malformed JSON payload")
            
            # Validate JSON depth
            is_valid, msg = InputValidator.validate_json_depth(payload)
            if not is_valid:
                raise HTTPException(status_code=400, detail=msg)
            
            # Validate string lengths
            is_valid, msg = InputValidator.validate_string_length(payload)
            if not is_valid:
                raise HTTPException(status_code=400, detail=msg)
            
        elif self.config['data_type'] == 'blob':
            payload = body
            # Additional blob handling...
        else:
            raise HTTPException(status_code=415, detail="Unsupported data type")

        # Get the module from registry
        module_name = self.config['module']
        try:
            module_class = ModuleRegistry.get(module_name)
        except KeyError:
            raise HTTPException(status_code=501, detail=f"Unsupported module: {module_name}")
        
        # Instantiate and process
        # Add webhook_id to config for modules that need it (e.g., ClickHouse)
        module_config = {**self.config, '_webhook_id': self.webhook_id}
        module = module_class(module_config)
        
        # Get retry configuration
        retry_config = self.config.get("retry", {})
        
        # If retry is enabled, execute with retry handler
        if retry_config.get("enabled", False):
            # Execute module with retry logic
            async def execute_module():
                return await retry_handler.execute_with_retry(
                    module.process,
                    payload,
                    dict(self.headers.items()),
                    retry_config=retry_config
                )
            
            # Execute with retry (fire-and-forget, but track result)
            task = asyncio.create_task(execute_module())
            
            # Return payload, headers, and task for status checking
            return payload, dict(self.headers.items()), task
        else:
            # No retry configured, execute normally (fire-and-forget)
            asyncio.create_task(module.process(payload, dict(self.headers.items())))
            return payload, dict(self.headers.items()), None
