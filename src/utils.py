import requests
import uuid

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