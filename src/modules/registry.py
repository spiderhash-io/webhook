import re
from typing import Any, Dict, Type
from src.modules.base import BaseModule
from src.modules.log import LogModule
from src.modules.save_to_disk import SaveToDiskModule
from src.modules.rabbitmq_module import RabbitMQModule
from src.modules.redis_rq import RedisRQModule
from src.modules.redis_publish import RedisPublishModule
from src.modules.http_webhook import HTTPWebhookModule
from src.modules.kafka import KafkaModule
from src.modules.s3 import S3Module
from src.modules.websocket import WebSocketModule
from src.modules.clickhouse import ClickHouseModule


class ModuleRegistry:
    """Registry for webhook processing modules."""
    
    _modules: Dict[str, Type[BaseModule]] = {
        'log': LogModule,
        'save_to_disk': SaveToDiskModule,
        'rabbitmq': RabbitMQModule,
        'redis_rq': RedisRQModule,
        'http_webhook': HTTPWebhookModule,
        'kafka': KafkaModule,
        's3': S3Module,
        'redis_publish': RedisPublishModule,
        'clickhouse': ClickHouseModule,
        'websocket': WebSocketModule,
    }
    
    @classmethod
    def register(cls, name: str, module_class: Type[BaseModule]) -> None:
        """
        Register a new module.
        
        This method validates the module name before registration to ensure
        it meets security requirements.
        
        Args:
            name: The module name (used in webhook config)
            module_class: The module class (must inherit from BaseModule)
            
        Raises:
            ValueError: If module name is invalid or module_class doesn't inherit from BaseModule
        """
        # Validate module name
        validated_name = cls._validate_module_name(name)
        
        # Validate module class
        if not issubclass(module_class, BaseModule):
            raise ValueError(f"Module {module_class} must inherit from BaseModule")
        
        cls._modules[validated_name] = module_class
    
    @classmethod
    def _validate_module_name(cls, name: str) -> str:
        """
        Validate module name to prevent injection attacks.
        
        This function:
        - Validates format (alphanumeric, underscore, hyphen only)
        - Enforces length limits to prevent DoS
        - Blocks path traversal patterns
        - Blocks dangerous characters
        
        Args:
            name: The module name to validate
            
        Returns:
            Validated module name
            
        Raises:
            ValueError: If module name is invalid or poses security risk
        """
        if not name or not isinstance(name, str):
            raise ValueError("Module name must be a non-empty string")
        
        # Strip whitespace
        name = name.strip()
        
        # Check for empty after stripping
        if not name:
            raise ValueError("Module name cannot be empty or whitespace-only")
        
        # Enforce maximum length to prevent DoS attacks
        MAX_MODULE_NAME_LENGTH = 64
        if len(name) > MAX_MODULE_NAME_LENGTH:
            raise ValueError(f"Module name too long: {len(name)} characters (max: {MAX_MODULE_NAME_LENGTH})")
        
        # Minimum length
        if len(name) < 1:
            raise ValueError("Module name too short")
        
        # Block path traversal patterns FIRST (before format check)
        if '..' in name or '/' in name or '\\' in name:
            raise ValueError("Module name cannot contain path traversal characters (.., /, \\)")
        
        # Block null bytes
        if '\x00' in name:
            raise ValueError("Module name cannot contain null bytes")
        
        # Only allow alphanumeric, underscore, and hyphen
        # Must start with alphanumeric (not underscore or hyphen)
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_-]*$', name):
            raise ValueError(
                "Invalid module name format. Must start with alphanumeric and contain only alphanumeric, underscore, and hyphen characters"
            )
        
        # Block consecutive special characters (--, __)
        if re.search(r'--+', name) or re.search(r'__+', name):
            raise ValueError("Module name cannot contain consecutive underscores or hyphens")
        
        # Block names that are only special characters
        if re.match(r'^[-_]+$', name):
            raise ValueError("Module name cannot consist only of underscores or hyphens")
        
        return name
    
    @classmethod
    def get(cls, name: str) -> Type[BaseModule]:
        """
        Get a module class by name.
        
        This method validates the module name before lookup to prevent
        injection attacks and unauthorized module access.
        
        Args:
            name: The module name
            
        Returns:
            The module class
            
        Raises:
            ValueError: If module name is invalid or poses security risk
            KeyError: If module is not registered
        """
        # Validate module name first to prevent injection
        validated_name = cls._validate_module_name(name)
        
        # Look up in registry
        if validated_name not in cls._modules:
            raise KeyError(f"Module '{validated_name}' is not registered")
        
        return cls._modules[validated_name]
    
    @classmethod
    def list_modules(cls) -> list:
        """List all registered module names."""
        return list(cls._modules.keys())
