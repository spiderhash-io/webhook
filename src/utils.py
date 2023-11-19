import requests
import uuid
import os
import re

def count_words_at_url(url):
    resp = requests.get(url)
    txt = len(resp.text.split())
    print(txt)
    return txt


async def save_to_disk(payload, config):
    myuuid = uuid.uuid4()

    with open(str(myuuid)+".txt", mode="w") as f:
        f.write(str(payload))    
        f.flush()
        f.close()


async def background_task(payload, config):
    await asyncio.sleep(5)  # Simulating delay
    print("hello")

def load_env_vars(data):
    # Regular expression to match the placeholder pattern
    pattern = re.compile(r'^\{\$(\w+)\}$')

    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, str):
                match = pattern.match(value)
                if match:
                    # Replace with environment variable if pattern matches
                    env_var = match.group(1)
                    data[key] = os.getenv(env_var, f'Undefined variable {env_var}')
            else:
                # Recursive call for nested dictionaries or lists
                load_env_vars(value)
    elif isinstance(data, list):
        for item in data:
            load_env_vars(item)

    return data


# SECRET_KEY = "your-secret-key"  # Replace with your secret key

def verify_hmac(body, received_signature):
    """
    Verify HMAC signature of the request body.
    """
    # Create a new hmac object using the secret key and the SHA256 hash function
    hmac_obj = hmac.new(SECRET_KEY.encode(), body, hashlib.sha256)
    # Compute the HMAC signature
    computed_signature = hmac_obj.hexdigest()
    # Compare the computed signature with the received signature
    return hmac.compare_digest(computed_signature, received_signature)



# async def your_endpoint(request: Request, x_hmac_signature: str = Header(None)):
#     # Read the request body
#     body = await request.body()
#
#     # Verify HMAC
#     if not verify_hmac(body, x_hmac_signature):
#         raise HTTPException(status_code=401, detail="Invalid HMAC signature")