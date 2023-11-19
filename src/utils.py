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
