# subscribe to redis pubsub, and print results

# first, run this demo with `python async_redis.py`

# second, connect to redis with redis-cli, then `publish test_channel 123`.
# this program will output 123.

# third, switch to redis-cli, and input 'publish test_channel exit'.
# this program will be ended.

import asyncio

import asyncio_redis

loop = asyncio.get_event_loop()

class Listener(object):

    def __init__(self, host=None, port=None):
        self.host = host or 'localhost'
        self.port = port or 6379

    async def __call__(self, *args, **kwargs):
        redis_cli = await asyncio_redis.Connection.create(self.host, self.port)

        subscriber = await redis_cli.start_subscribe()
        await subscriber.subscribe(['test_channel'])

        while True:
            reply = await subscriber.next_published()
            print('receive {}, on channel {}'.format(reply.value, reply.channel))
            if reply.value == 'exit':
                redis_cli.close()
                return 'exit'

listener = Listener()

loop.run_until_complete(listener())

