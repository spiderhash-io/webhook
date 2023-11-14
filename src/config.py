from src.modules.rabbitmq import RabbitMQConnectionPool

# data type [ "text", "json", "blob", "form" ]
# processing modules [ "rmq","kafka","redis","save_to_disk", "save_to_db", "websocket" ]
# authorization [ "basic", "secret", "JWT", "HMAC" ]

# Mock of the configuration data structure
webhook_config_data = {
    'abcde': {
        'data_type': 'json',
        'module': 'save_to_disk',
        'module-config': {
            "path": "webhooks"
        },
        'authorization': 'secret'
    },
    'toredis': {
        'data_type': 'json',
        'module': 'redis_rq',
        'connection': 'redis-local'
    },
    'torabbit': {
        'data_type': 'json',
        'module': 'rabbitmq',
        'connection': 'rabbitmq-local',
        'queue_name': 'webhooks'
    },
    'torabbit2': {
        'data_type': 'json',
        'module': 'rabbitmq',
        'connection': 'rabbitmq-local2',
        'queue_name': 'webhooks2'
    },
    'workflow': {
        'data_type': 'json',
        'module': 'temporalio',
        'connection': 'rabbitmq-local2',
        'queue_name': 'webhooks2'
    }
}

# connection config
connection_config = {
    # 'redis-local': {
    #     'type': 'redis-rq',
    #     'host': '0.0.0.0',
    #     'port': '6379',
    #     'db': '0',
    #     'queue_name': 'beta',
    # },
    'rabbitmq-local': {
        'type': 'rabbitmq',
        'host': '0.0.0.0',
        'port': '5672',
        'user': 'guest',
        'pass': 'guest',
        
    },
    'rabbitmq-local2': {
        'type': 'rabbitmq',
        'host': '0.0.0.0',
        'port': '5672',
        'user': 'guest',
        'pass': 'guest',
        
    },
}




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
