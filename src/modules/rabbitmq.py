import aio_pika
from aio_pika import connect_robust
from aio_pika.pool import Pool
# import aio_pika
import asyncio
import json
import time
from typing import Optional


class RabbitMQConnectionPool:
    """
    RabbitMQ connection pool with exhaustion protection.
    
    Features:
    - Configurable pool size limits
    - Connection acquisition timeout
    - Pool usage monitoring
    - Circuit breaker pattern for exhaustion scenarios
    """
    
    def __init__(self, max_size=3, acquisition_timeout=30.0, circuit_breaker_threshold=0.8):
        """
        Initialize connection pool.
        
        Args:
            max_size: Maximum number of connections in the pool
            acquisition_timeout: Maximum time (seconds) to wait for a connection
            circuit_breaker_threshold: Fraction of pool usage that triggers circuit breaker (0.0-1.0)
        """
        self.max_size = max_size
        self.acquisition_timeout = acquisition_timeout
        self.circuit_breaker_threshold = circuit_breaker_threshold
        self.connections = asyncio.Queue(maxsize=max_size)
        
        # Monitoring metrics
        self._total_requests = 0
        self._successful_acquisitions = 0
        self._timeout_errors = 0
        self._circuit_breaker_triggered = False
        self._last_exhaustion_time = None
        
        # Lock for metrics updates
        self._metrics_lock = asyncio.Lock()

    async def create_pool(self, host='localhost', port=5672, login='guest', password='guest'):
        """Initialize connections and put them in the queue."""
        for _ in range(self.max_size):
            connection = await connect_robust(
                f"amqp://{login}:{password}@{host}:{port}/",
                # loop=self.loop
            )
            await self.connections.put(connection)

    async def get_connection(self, timeout: Optional[float] = None) -> Optional[aio_pika.Connection]:
        """
        Acquire a connection from the pool with timeout protection.
        
        Args:
            timeout: Optional timeout override (uses self.acquisition_timeout if None)
            
        Returns:
            Connection object or None if timeout/limit exceeded
            
        Raises:
            asyncio.TimeoutError: If connection cannot be acquired within timeout
            Exception: If circuit breaker is triggered
        """
        timeout = timeout or self.acquisition_timeout
        
        async with self._metrics_lock:
            self._total_requests += 1
            
            # Check circuit breaker (only block if already triggered)
            if self._circuit_breaker_triggered:
                # Check if enough time has passed to reset circuit breaker
                if self._last_exhaustion_time:
                    time_since_exhaustion = time.time() - self._last_exhaustion_time
                    if time_since_exhaustion > 60:  # Reset after 60 seconds
                        self._circuit_breaker_triggered = False
                        self._last_exhaustion_time = None
                    else:
                        raise Exception(
                            f"Connection pool circuit breaker active. "
                            f"Pool exhausted {int(time_since_exhaustion)}s ago. "
                            f"Please retry later."
                        )
            
            # Check pool usage (connections in use / max_size) - just log warning, don't block
            available = self.connections.qsize()
            pool_usage = (self.max_size - available) / self.max_size if self.max_size > 0 else 0.0
            if pool_usage >= self.circuit_breaker_threshold and not self._circuit_breaker_triggered:
                # Log warning but don't block - let the actual timeout trigger circuit breaker
                print(
                    f"WARNING: RabbitMQ connection pool usage ({pool_usage*100:.1f}%) "
                    f"exceeded threshold ({self.circuit_breaker_threshold*100:.1f}%). "
                    f"High usage detected."
                )
        
        try:
            # Try to get connection with timeout
            connection = await asyncio.wait_for(
                self.connections.get(),
                timeout=timeout
            )
            
            async with self._metrics_lock:
                self._successful_acquisitions += 1
            
            return connection
            
        except asyncio.TimeoutError:
            async with self._metrics_lock:
                self._timeout_errors += 1
                self._last_exhaustion_time = time.time()
                
                # Trigger circuit breaker if not already triggered
                if not self._circuit_breaker_triggered:
                    self._circuit_breaker_triggered = True
                    print(
                        f"WARNING: RabbitMQ connection pool timeout. "
                        f"All {self.max_size} connections are in use. "
                        f"Circuit breaker activated."
                    )
            
            # Raise as Exception (not TimeoutError) to match expected behavior
            raise Exception(
                f"Connection pool exhausted: Could not acquire connection within {timeout}s. "
                f"All {self.max_size} connections are in use. Please retry later."
            )

    async def release(self, connection):
        """
        Release the connection back into the pool.
        
        Args:
            connection: Connection to release
            
        Note:
            This should not block indefinitely. If the pool is full (which shouldn't happen),
            we log a warning but still try to put the connection back.
        """
        # Put connection back - this should not block if we're releasing correctly
        # (pool should have space since we got the connection from it)
        try:
            await self.connections.put(connection)
        except Exception as e:
            # If there's an error (e.g., pool is full), log and close connection
            print(
                f"WARNING: RabbitMQ connection pool error during release: {e}. "
                f"Closing connection."
            )
            try:
                await connection.close()
            except Exception:
                pass

    async def close_all(self):
        """Close all connections when shutting down the pool."""
        while not self.connections.empty():
            connection = await self.connections.get()
            try:
                await connection.close()
            except Exception:
                pass
    
    def get_metrics(self) -> dict:
        """
        Get pool usage metrics.
        
        Returns:
            Dictionary with pool metrics
        """
        # Use a synchronous approach to get metrics (no async lock needed for reading)
        # Note: qsize() is not async, so we can call it directly
        current_size = self.connections.qsize()
        # Pool usage = (connections in use) / max_size
        # connections in use = max_size - available = max_size - current_size
        pool_usage = (self.max_size - current_size) / self.max_size if self.max_size > 0 else 0.0
        
        return {
            "max_size": self.max_size,
            "current_size": current_size,  # Available connections
            "pool_usage_percent": pool_usage * 100,  # Percentage of connections in use
            "total_requests": self._total_requests,
            "successful_acquisitions": self._successful_acquisitions,
            "timeout_errors": self._timeout_errors,
            "circuit_breaker_active": self._circuit_breaker_triggered,
            "last_exhaustion_time": self._last_exhaustion_time,
        }


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
