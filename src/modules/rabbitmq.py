import aio_pika
from aio_pika import connect_robust
from aio_pika.pool import Pool
# import aio_pika
import asyncio
import json


class RabbitMQConnectionPool:
    def __init__(self, max_size=3):
        # self.loop = loop or asyncio.get_event_loop()
        self.max_size = max_size
        self.connections = asyncio.Queue(maxsize=max_size)

    async def create_pool(self, host='localhost', port=5672, login='guest', password='guest'):
        # Initialize connections and put them in the queue
        for _ in range(self.max_size):
            connection = await connect_robust(
                f"amqp://{login}:{password}@{host}:{port}/",
                # loop=self.loop
            )
            await self.connections.put(connection)

    async def get_connection(self):
        # Acquire a connection from the queue
        return await self.connections.get()

    async def release(self, connection):
        # Release the connection back into the pool
        await self.connections.put(connection)

    async def close_all(self):
        # Close all connections when shutting down the pool
        while not self.connections.empty():
            connection = await self.connections.get()
            await connection.close()


async def rabbitmq_publish(payload, config, headers):

    headers_dict = dict(headers.items())

    connection_pool = config.get('connection_details', {}).get("connection_pool")
    queue_name = config.get('queue_name')
    
    if not connection_pool:
        raise Exception("Connection pool is not defined")

    connection = await connection_pool.get_connection()

    if connection is None:
        raise Exception("Could not acquire a connection from the pool")

    try:
        # Create a new channel
        channel = await connection.channel()

        # Declare a queue (ensure it exists). Queue parameters need to be adjusted as per your setup.
        queue = await channel.declare_queue(queue_name, durable=True)

        # Serialize the payload to JSON
        json_body = json.dumps(payload).encode()
       

        # Create the message. You could add properties like delivery_mode=2 to make message persistent.
        message = aio_pika.Message(
            body=json_body,
            headers=headers_dict,
            delivery_mode=2
        )

        # Send the message. The routing_key needs to match the queue name if default exchange is used.
        await channel.default_exchange.publish(message, routing_key=queue_name)

        print("Message published to: " + str(queue_name))
    except Exception as e:
        print(f"Failed to publish message: {e}")
        raise e

    finally:
        # Always release the connection back to the pool
        await connection_pool.release(connection)
