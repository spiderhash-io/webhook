import requests
import uuid
import os
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta
import asyncio


def count_words_at_url(url):
    resp = requests.get(url)
    txt = len(resp.text.split())
    print(txt)
    return txt


async def save_to_disk(payload, config):
    my_uuid = uuid.uuid4()

    with open(str(my_uuid)+".txt", mode="w") as f:
        f.write(str(payload))    
        f.flush()
        f.close()


async def print_to_stdout(payload, headers, config):
    print("config: "+str(config))
    print("headers: "+str(headers))
    print("body: "+str(payload))
    # await asyncio.sleep(5)  # Simulating delay


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


class EndpointStats:
    def __init__(self):
        self.stats = defaultdict(lambda: defaultdict(int))
        self.timestamps = defaultdict(dict)  # Using dict for timestamps
        self.lock = asyncio.Lock()
        self.bucket_size = timedelta(minutes=1)  # Smallest bucket size

    async def increment(self, endpoint_name):
        async with self.lock:
            now = datetime.utcnow()
            bucket = self._get_bucket(now)
            self.timestamps[endpoint_name][bucket] = self.timestamps[endpoint_name].get(bucket, 0) + 1
            self.stats[endpoint_name]['total'] += 1
            self._cleanup_old_buckets(endpoint_name, now)  # Cleanup old buckets

    def _get_bucket(self, timestamp):
        # Align timestamp to the start of the bucket
        return timestamp - (timestamp - datetime.min) % self.bucket_size

    def _cleanup_old_buckets(self, endpoint_name, now):
        # Remove buckets older than a certain cutoff (e.g., 1 day)
        cutoff = now - timedelta(days=1)
        old_buckets = [time for time in self.timestamps[endpoint_name] if time < cutoff]
        for bucket in old_buckets:
            del self.timestamps[endpoint_name][bucket]

    def get_stats(self):
        stats_summary = defaultdict(dict)
        now = datetime.utcnow()
        for endpoint in self.timestamps:
            stats_summary[endpoint]['total'] = self.stats[endpoint]['total']
            stats_summary[endpoint]['minute'] = sum(count for time, count in self.timestamps[endpoint].items() if time > now - timedelta(minutes=1))
            stats_summary[endpoint]['5_minutes'] = sum(count for time, count in self.timestamps[endpoint].items() if time > now - timedelta(minutes=5))
            stats_summary[endpoint]['15_minutes'] = sum(count for time, count in self.timestamps[endpoint].items() if time > now - timedelta(minutes=15))
            stats_summary[endpoint]['30_minutes'] = sum(count for time, count in self.timestamps[endpoint].items() if time > now - timedelta(minutes=30))
            stats_summary[endpoint]['hour'] = sum(count for time, count in self.timestamps[endpoint].items() if time > now - timedelta(hours=1))
            stats_summary[endpoint]['day'] = sum(count for time, count in self.timestamps[endpoint].items() if time > now - timedelta(days=1))
            stats_summary[endpoint]['week'] = sum(count for time, count in self.timestamps[endpoint].items() if time > now - timedelta(weeks=1))
            stats_summary[endpoint]['month'] = sum(count for time, count in self.timestamps[endpoint].items() if time > now - timedelta(days=30))

        return stats_summary


# SECRET_KEY = "your-secret-key"  # Replace with your secret key

# def verify_hmac(body, received_signature):
#     """
#     Verify HMAC signature of the request body.
#     """
#     # Create a new hmac object using the secret key and the SHA256 hash function
#     hmac_obj = hmac.new(SECRET_KEY.encode(), body, hashlib.sha256)
#     # Compute the HMAC signature
#     computed_signature = hmac_obj.hexdigest()
#     # Compare the computed signature with the received signature
#     return hmac.compare_digest(computed_signature, received_signature)


# async def your_endpoint(request: Request, x_hmac_signature: str = Header(None)):
#     # Read the request body
#     body = await request.body()
#
#     # Verify HMAC
#     if not verify_hmac(body, x_hmac_signature):
#         raise HTTPException(status_code=401, detail="Invalid HMAC signature")
