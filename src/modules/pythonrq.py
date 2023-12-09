
from redis import Redis
from rq import Queue
from src.utils import count_words_at_url


async def redis_rq(payload, config):

    connection_details = config.get('connection_details')

    q = Queue(connection=connection_details['conn'])
    result = q.enqueue(count_words_at_url, 'http://nvie.com')

    print("redis_rq_module")