from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import JSONResponse
import asyncio
import time
import json
from redis import Redis
from rq import Queue

from src.config import inject_connection_details, webhook_config_data, connection_config
from src.modules.rabbitmq import RabbitMQConnectionPool, rabbitmq_publish
from src.utils import count_words_at_url, save_to_disk, background_task


app = FastAPI()


@app.on_event("startup")
async def startup_event():
    global webhook_config_data
    webhook_config_data = await inject_connection_details(webhook_config_data, connection_config)
    print(webhook_config_data)


@app.post("/webhook/{webhook_id}")
async def read_webhook(webhook_id: str,  request: Request, authorization: str = Header(...)):

    # Get the config for the webhook_id
    config = webhook_config_data.get(webhook_id)
    if not config:
        return HTTPException(status_code=404, detail="Webhook ID not found")

    # load data
    headers = request.headers
    body = await request.body()

    # return {"headers": dict(headers)}

    # debug
    # print(
    #     "id:", webhook_id,  "\n"
    #     "auth:", authorization, "\n"
    #     "body: ", headers, "\n"
    #     "body: ", body, "\n"
    # )


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

    # do stuff here in background
    
    # Execute the relevant module function
    if config['module'] == 'save_to_disk':
        asyncio.create_task(save_to_disk(payload, config))
    elif config['module'] == 'log':
        asyncio.create_task(background_task(payload, config))
    elif config['module'] == 'redis_rq':
        asyncio.create_task(redis_rq(payload, config))
    elif config['module'] == 'rabbitmq':
        asyncio.create_task(rabbitmq_publish(payload, config, headers))
    else:
        return HTTPException(status_code=501, detail="Unsupported module")

   

    # return success
    return JSONResponse(content={"message": "200 OK"})