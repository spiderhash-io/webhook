import json
import re
from typing import Any, Dict
from aiokafka import AIOKafkaProducer
from src.modules.base import BaseModule


class KafkaModule(BaseModule):
    """Module for publishing webhook payloads to Apache Kafka."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.producer = None
        # Validate topic name during initialization to fail early
        raw_topic = self.config.get('topic')
        if raw_topic is not None:
            # Validate even if empty string (will raise ValueError)
            self._validated_topic = self._validate_topic_name(raw_topic)
        else:
            # None is allowed but will fail in process() method
            self._validated_topic = None
    
    def _validate_topic_name(self, topic_name: str) -> str:
        """
        Validate and sanitize Kafka topic name to prevent injection.
        
        Args:
            topic_name: The topic name from configuration
            
        Returns:
            Validated and sanitized topic name
            
        Raises:
            ValueError: If topic name is invalid or contains dangerous characters
        """
        if not topic_name or not isinstance(topic_name, str):
            raise ValueError("Topic name must be a non-empty string")
        
        # Remove whitespace
        topic_name = topic_name.strip()
        
        if not topic_name:
            raise ValueError("Topic name cannot be empty")
        
        # Maximum length to prevent DoS (Kafka limit is typically 249 characters)
        if len(topic_name) > 249:
            raise ValueError(f"Topic name too long: {len(topic_name)} characters (max: 249)")
        
        # Validate format: alphanumeric, underscore, hyphen, and dot only
        # Kafka allows more characters, but we restrict for security
        # Valid characters: letters, numbers, underscore, hyphen, dot
        if not re.match(r'^[a-zA-Z0-9_\-\.]+$', topic_name):
            raise ValueError(
                f"Invalid topic name format: '{topic_name}'. "
                f"Only alphanumeric characters, underscores, hyphens, and dots are allowed."
            )
        
        # Reject dangerous patterns that could be used for injection
        dangerous_patterns = ['..', '--', ';', '/*', '*/', '(', ')', '[', ']', '{', '}', '|', '&', '$', '`', '\\', '/', ':', '@', '#', '%']
        for pattern in dangerous_patterns:
            if pattern in topic_name:
                raise ValueError(f"Topic name contains dangerous pattern: '{pattern}'")
        
        # Reject Kafka command keywords that could be used in injection
        kafka_keywords = [
            'create', 'delete', 'describe', 'list', 'alter', 'config', 'produce', 'consume',
            'console-producer', 'console-consumer', 'kafka-topics', 'kafka-configs'
        ]
        topic_name_lower = topic_name.lower()
        for keyword in kafka_keywords:
            # Check if keyword appears as a standalone word or at the start
            if topic_name_lower == keyword or topic_name_lower.startswith(keyword + '.') or topic_name_lower.startswith(keyword + '_') or topic_name_lower.startswith(keyword + '-'):
                raise ValueError(f"Topic name contains forbidden Kafka keyword: '{keyword}'")
        
        # Reject patterns that look like command injection
        if any(char in topic_name for char in ['\r', '\n', '\0', '\t']):
            raise ValueError("Topic name contains forbidden control characters")
        
        # Reject topic names that are too short (Kafka requires at least 1 character, but we'll require 2 for safety)
        if len(topic_name) < 2:
            raise ValueError("Topic name too short (minimum 2 characters)")
        
        return topic_name
    
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
        topic = self._validated_topic
        
        if not topic:
            raise ValueError("Kafka topic is required and must be validated")
        
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
            # Log detailed error server-side
            print(f"Failed to publish message to Kafka: {e}")
            # Raise generic error to client (don't expose Kafka details)
            from src.utils import sanitize_error_message
            raise Exception(sanitize_error_message(e, "Kafka operation"))
