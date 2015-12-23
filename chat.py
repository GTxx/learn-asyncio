import asyncio
import asyncio_redis
from aiohttp import web


class User(object):
    def __init__(self, user_id, ws_resp, channel, host='localhost', port=6379):
        self.host = host
        self.port = port
        self.user_id = user_id
        self.ws_resp = ws_resp
        self.channel = channel

    async def __call__(self, *args, **kwargs):
        # TODO: how to shutdown task(handle_redis_pub and handle_ws) when
        # websocket is closed or exceptions occur

        # init redis client

        await asyncio.gather(self.handle_redis_pub(),
                             self.handle_ws())
        return True

    async def handle_redis_pub(self):
        # init redis pub sub, use subscriber to listen to channel
        redis_cli = await asyncio_redis.Connection.create('localhost', 6379)
        subscriber = await redis_cli.start_subscribe()
        await subscriber.subscribe([self.channel])

        while True:
            reply = await subscriber.next_published()
            print('user {} receive {}, on channel {}'.format(self.user_id, reply.value, reply.channel))
            self.ws_resp.send_str(reply.value)
        redis_cli.close()

    async def handle_ws(self):
        redis_cli = await asyncio_redis.Connection.create('localhost', 6379)
        while True:
            msg = await self.ws_resp.receive()
            print('user {} send {} to channel {}'.format(self.user_id, msg.data, self.channel))
            await redis_cli.publish(self.channel, msg.data)
        redis_cli.close()

    def close(self):
        self.shudown = True

# user_id = 0
# def abc():
#     a = user_id
#
# async def ws_channel_handler(request):
#     channel_id = request.match_info['channel_id']
#     resp = web.WebSocketResponse()
#     ok, protocal = resp.can_prepare(request)
#     if not ok:
#         return 'bad msg, start websocket fail'
#     # response to client and set up websocket connection
#     await resp.prepare(request)
#     user = User(user_id, resp, channel_id)
#     user_id = user_id + 1
#     await user()

class WebSocketChannelHandler(object):

    def __init__(self):
        self.user_id = 1

    async def __call__(self, request, *args, **kwargs):
        channel_id = request.match_info['channel_id']
        resp = web.WebSocketResponse()
        ok, protocal = resp.can_prepare(request)
        if not ok:
            return 'bad msg, start websocket fail'
        # response to client and set up websocket connection
        await resp.prepare(request)
        user = User(self.user_id, resp, channel_id)
        self.user_id = self.user_id + 1
        await user()


async def index(request):
    with open('index.html', 'rb') as fp:
        return web.Response(body=fp.read(), content_type='text/html')

async def init(loop):
    app = web.Application(loop=loop)
    app['sockets'] = []
    app.router.add_route('GET', '/channel/{channel_id}', WebSocketChannelHandler())
    app.router.add_route('GET', '/', index)

    handler = app.make_handler()
    srv = await loop.create_server(handler, '127.0.0.1', 8080)
    print("Server started at http://127.0.0.1:8080")
    return app, srv, handler




if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    app, srv, handler = loop.run_until_complete(init(loop))
    loop.run_forever()
