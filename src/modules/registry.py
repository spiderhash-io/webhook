from typing import Any, Dict, Type
from src.modules.base import BaseModule
from src.modules.log import LogModule
from src.modules.save_to_disk import SaveToDiskModule
from src.modules.rabbitmq_module import RabbitMQModule
from src.modules.redis_rq import RedisRQModule
from src.modules.http_webhook import HTTPWebhookModule
from src.modules.kafka import KafkaModule
from src.modules.s3 import S3Module
from src.modules.websocket import WebSocketModule


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
        'websocket': WebSocketModule,
    }
    
    @classmethod
    def register(cls, name: str, module_class: Type[BaseModule]) -> None:
        """
        Register a new module.
        
        Args:
            name: The module name (used in webhook config)
            module_class: The module class (must inherit from BaseModule)
        """
        if not issubclass(module_class, BaseModule):
            raise ValueError(f"Module {module_class} must inherit from BaseModule")
        cls._modules[name] = module_class
    
    @classmethod
    def get(cls, name: str) -> Type[BaseModule]:
        """
        Get a module class by name.
        
        Args:
            name: The module name
            
        Returns:
            The module class
            
        Raises:
            KeyError: If module is not registered
        """
        if name not in cls._modules:
            raise KeyError(f"Module '{name}' is not registered")
        return cls._modules[name]
    
    @classmethod
    def list_modules(cls) -> list:
        """List all registered module names."""
        return list(cls._modules.keys())
