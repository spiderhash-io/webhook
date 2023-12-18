from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
import asyncio
from datetime import datetime

from src.webhook import WebhookHandler
from src.config import inject_connection_details, webhook_config_data, connection_config
from src.utils import EndpointStats

app = FastAPI()
stats = EndpointStats()


async def cleanup_task():
    while True:
        now = datetime.utcnow()
        async with stats.lock:
            for endpoint in stats.timestamps:
                stats._cleanup_old_buckets(endpoint, now)
        print("Cleaning up old buckets")
        await asyncio.sleep(3600)  # Wait for 1 hour (3600 seconds) before next cleanup


@app.on_event("startup")
async def startup_event():
    global webhook_config_data
    webhook_config_data = await inject_connection_details(webhook_config_data, connection_config)
    print(webhook_config_data)

    asyncio.create_task(cleanup_task())


@app.post("/webhook/{webhook_id}")
async def read_webhook(webhook_id: str,  request: Request):

    try:
        webhook_handler = WebhookHandler(
            webhook_id,
            webhook_config_data,
            connection_config,
            request,
        )
    except HTTPException as e:
        raise e

    is_valid, message = await webhook_handler.validate_webhook()
    if not is_valid:
        raise HTTPException(status_code=401, detail=message)

    await webhook_handler.process_webhook()

    await stats.increment(webhook_id)

    return JSONResponse(content={"message": "200 OK"})


# @app.post("/webhook/{webhook_id}")
# async def read_webhook(webhook_id: str,  request: Request):
#     # load headers
#     headers = request.headers
#
#     # body = await request.body()
#
#     # Get the config for the webhook_id
#     config = webhook_config_data.get(webhook_id)
#     if not config:
#         return HTTPException(status_code=404, detail="Webhook ID not found")
#
#     # if authorization:
#     # Extract the expected authorization value from the configuration
#     expected_auth = config.get("authorization", {})
#
#     if expected_auth:
#         authorization_header = headers.get('Authorization')
#
#         # Optional: Check for "Bearer" in the header
#         if "Bearer" in expected_auth and not authorization_header.startswith("Bearer"):
#             raise HTTPException(status_code=401, detail="Unauthorized: Bearer token required")
#
#         # Compare the provided authorization header with the expected value
#         if authorization_header != expected_auth:
#             raise HTTPException(status_code=401, detail="Unauthorized")
#
#     # Read the incoming data based on its type
#     if config['data_type'] == 'json':
#         try:
#             payload = json.loads(await request.body())
#         except json.JSONDecodeError:
#             return HTTPException(status_code=400, detail="Malformed JSON payload")
#     elif config['data_type'] == 'blob':
#         payload = await request.body()
#         # TODO blob
#     else:
#         return HTTPException(status_code=415, detail="Unsupported data type")
#
#     # Execute the relevant module function
#     if config['module'] == 'save_to_disk':
#         asyncio.create_task(save_to_disk(payload, config))
#     elif config['module'] == 'log':
#         asyncio.create_task(print_to_stdout(payload, headers, config))
#     elif config['module'] == 'redis_rq':
#         asyncio.create_task(redis_rq(payload, config))
#     elif config['module'] == 'rabbitmq':
#         asyncio.create_task(rabbitmq_publish(payload, config, headers))
#     else:
#         return HTTPException(status_code=501, detail="Unsupported module")
#
#     # Update statistics after processing the webhook
#     await stats.increment(webhook_id)
#
#     # return success
#     return JSONResponse(content={"message": "200 OK"})


@app.get("/")
async def default_endpoint():
    return JSONResponse(content={"message": "200 OK"})


@app.get("/stats")
async def stats_endpoint():
    return stats.get_stats()



