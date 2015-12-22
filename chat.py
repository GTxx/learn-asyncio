import asyncio
import asyncio_redis
from aiohttp import web

loop = asyncio.get_event_loop()

class User(object):
    def __init__(self, user_id, ws_resp, channel, host='localhost', port=6379):
        self.host = host
        self.port = port
        self.user_id = user_id
        self.ws_resp = ws_resp
        self.channel = channel

    async def __call__(self, *args, **kwargs):
        # init redis client
        redis_cli = await asyncio_redis.Connection.create('localhost', 6379)

        await asyncio.gather(self.handle_redis_pub(redis_cli),
                             self.handle_ws(redis_cli))
        return True

    async def handle_redis_pub(self, redis_cli):
        # init redis pub sub, use subscriber to listen to channel
        subscriber = await redis_cli.start_subscribe()
        await subscriber.subscribe([self.channel])

        while True:
            reply = await subscriber.next_published()
            print('receive {}, on channel {}'.format(reply.value, reply.channel))
            self.ws_resp.send_str(reply.value)

    async def handle_ws(self, redis_cli):
        while True:
            msg = await self.ws_resp.receive()
            await redis_cli.publish(msg.data, self.channel)

    def close(self):
        self.shudown = True


async def ws_channel_handler(request):
    channel_id = request.match_info['channel_id']
    resp = web.WebSocketResponse()
    ok, protocal = resp.can_prepare(request)
    if not ok:
        return 'bad msg, start websocket fail'
    user = User(123, resp, channel_id)
    await user()


async def index(request):
    with open('index.html', 'rb') as fp:
        return web.Response(body=fp.read(), content_type='text/html')

async def init(loop):
    app = web.Application(loop=loop)
    app['sockets'] = []
    app.router.add_route('GET', '/channel/{channel_id}', ws_channel_handler)
    app.router.add_route('GET', '/', )

    handler = app.make_handler()
    srv = await loop.create_server(handler, '127.0.0.1', 8080)
    print("Server started at http://127.0.0.1:8080")
    return app, srv, handler
loop.run()