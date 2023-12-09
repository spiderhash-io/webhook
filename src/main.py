from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
import asyncio
import json


from src.config import inject_connection_details, webhook_config_data, connection_config
from src.modules.rabbitmq import rabbitmq_publish
from src.modules.pythonrq import redis_rq
from src.utils import save_to_disk, print_to_stdout

app = FastAPI()


@app.on_event("startup")
async def startup_event():
    global webhook_config_data
    webhook_config_data = await inject_connection_details(webhook_config_data, connection_config)
    print(webhook_config_data)


@app.post("/webhook/{webhook_id}")
async def read_webhook(webhook_id: str,  request: Request):
    # load headers
    headers = request.headers

    # body = await request.body()

    # Get the config for the webhook_id
    config = webhook_config_data.get(webhook_id)
    if not config:
        return HTTPException(status_code=404, detail="Webhook ID not found")

    # if authorization:
    # Extract the expected authorization value from the configuration
    expected_auth = config.get("authorization", {})

    if expected_auth:
        authorization_header = headers.get('Authorization')

        # Optional: Check for "Bearer" in the header
        if "Bearer" in expected_auth and not authorization_header.startswith("Bearer"):
            raise HTTPException(status_code=401, detail="Unauthorized: Bearer token required")

        # Compare the provided authorization header with the expected value
        if authorization_header != expected_auth:
            raise HTTPException(status_code=401, detail="Unauthorized")

    # Read the incoming data based on its type
    if config['data_type'] == 'json':
        try:
            payload = json.loads(await request.body())
        except json.JSONDecodeError:
            return HTTPException(status_code=400, detail="Malformed JSON payload")
    elif config['data_type'] == 'blob':
        payload = await request.body()
        # TODO blob
    else:
        return HTTPException(status_code=415, detail="Unsupported data type")

    # Execute the relevant module function
    if config['module'] == 'save_to_disk':
        asyncio.create_task(save_to_disk(payload, config))
    elif config['module'] == 'log':
        asyncio.create_task(print_to_stdout(payload, headers, config))
    elif config['module'] == 'redis_rq':
        asyncio.create_task(redis_rq(payload, config))
    elif config['module'] == 'rabbitmq':
        asyncio.create_task(rabbitmq_publish(payload, config, headers))
    else:
        return HTTPException(status_code=501, detail="Unsupported module")

    # return success
    return JSONResponse(content={"message": "200 OK"})
