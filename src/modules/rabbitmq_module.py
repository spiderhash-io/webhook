import aio_pika
import json
from typing import Any, Dict
from src.modules.base import BaseModule


class RabbitMQModule(BaseModule):
    """Module for publishing webhook payloads to RabbitMQ."""
    
    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        """Publish payload to RabbitMQ queue."""
        headers_dict = dict(headers.items())
        
        connection_pool = self.connection_details.get("connection_pool")
        queue_name = self.config.get('queue_name')
        
        if not connection_pool:
            raise Exception("Connection pool is not defined")

        connection = await connection_pool.get_connection()

        if connection is None:
            raise Exception("Could not acquire a connection from the pool")

        try:
            # Create a new channel
            channel = await connection.channel()

            # Declare a queue (ensure it exists)
            queue = await channel.declare_queue(queue_name, durable=True)

            # Serialize the payload to JSON
            json_body = json.dumps(payload).encode()

            # Create the message
            message = aio_pika.Message(
                body=json_body,
                headers=headers_dict,
                delivery_mode=2
            )

            # Send the message
            await channel.default_exchange.publish(message, routing_key=queue_name)

            print("Message published to: " + str(queue_name))
        except Exception as e:
            print(f"Failed to publish message: {e}")
            raise e
        finally:
            # Always release the connection back to the pool
            await connection_pool.release(connection)
