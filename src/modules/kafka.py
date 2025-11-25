import json
from typing import Any, Dict
from aiokafka import AIOKafkaProducer
from src.modules.base import BaseModule


class KafkaModule(BaseModule):
    """Module for publishing webhook payloads to Apache Kafka."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.producer = None
    
    async def setup(self) -> None:
        """Initialize Kafka producer."""
        bootstrap_servers = self.connection_details.get('bootstrap_servers', 'localhost:9092')
        
        self.producer = AIOKafkaProducer(
            bootstrap_servers=bootstrap_servers,
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
        await self.producer.start()
    
    async def teardown(self) -> None:
        """Close Kafka producer."""
        if self.producer:
            await self.producer.stop()
    
    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        """Publish payload to Kafka topic."""
        topic = self.config.get('topic')
        
        if not topic:
            raise Exception("Kafka topic not specified in configuration")
        
        # Get or create producer
        if not self.producer:
            await self.setup()
        
        try:
            # Prepare message
            key = self.module_config.get('key')
            partition = self.module_config.get('partition')
            
            # Prepare Kafka headers
            kafka_headers = []
            if self.module_config.get('forward_headers', False):
                kafka_headers = [(k, v.encode('utf-8')) for k, v in headers.items()]
            
            # Send message
            await self.producer.send(
                topic,
                value=payload,
                key=key.encode('utf-8') if key else None,
                partition=partition,
                headers=kafka_headers or None
            )
            
            # Flush to ensure delivery
            await self.producer.flush()
            
            print(f"Message published to Kafka topic: {topic}")
            
        except Exception as e:
            print(f"Failed to publish message to Kafka: {e}")
            raise e
