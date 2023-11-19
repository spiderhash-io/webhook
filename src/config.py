import json
from src.utils import load_env_vars
from src.modules.rabbitmq import RabbitMQConnectionPool
import os
from dotenv import load_dotenv
load_dotenv()

# data type [ "text", "json", "blob", "form" ]
# processing modules [ "rmq","kafka","redis","save_to_disk", "save_to_db", "websocket" ]
# authorization [ "basic", "secret", "JWT", "HMAC" ]

with open("webhooks.json", 'r') as webhooks_file:
    webhook_config_data = json.load(webhooks_file)

with open("connections.json", 'r') as connections_file:
    connection_config = json.load(connections_file)

# Update the configuration with environment variables
connection_config = load_env_vars(connection_config)

async def inject_connection_details(webhook_config_data, connection_config):
    # Iterate over webhook configuration items
    for webhook_id, config in webhook_config_data.items():
        # Check if 'connection' is in the webhook configuration
        connection_name = config.get('connection')
        if connection_name:
            # Find the corresponding connection details
            connection_details = connection_config.get(connection_name)
            if connection_details:
                
                # create connection pool redis rq
                if connection_details['type'] == "redis-rq":
                    # Initialize a Redis connection pool
                    connection_details["conn"] = Redis(
                        host=connection_details["host"],
                        port=connection_details["port"],
                        db=connection_details["db"]
                    )
                
                # create connection pool rabbitmq
                if connection_details['type'] == "rabbitmq":
                    
                    # Initialize RabbitMQ connection pool globally
                    connection_details["connection_pool"] = RabbitMQConnectionPool()

                    await connection_details["connection_pool"].create_pool(
                        host=connection_details["host"],
                        port=connection_details["port"],
                        login=connection_details["user"],
                        password=connection_details["pass"]
                    )

                # Inject the connection details into the webhook configuration
                config['connection_details'] = connection_details

                       

    return webhook_config_data
