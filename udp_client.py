import asyncio


class UDPClientProtocal(asyncio.DatagramProtocol):
    def __init__(self, send_data, loop=None):
        self.transport = None
        self.send_data = send_data
        self.loop = loop

    def connection_made(self, transport):
        print("connection made")
        self.transport = transport
        # start peroid data sending
        self.task = asyncio.ensure_future(self.periodic())

    def connection_lost(self, exc):
        print("connection lost")
        self.transport.close()
        self.task.cancel()

    def error_received(self, exc):
        pass

    def datagram_received(self, data, addr):
        print("receive data {} from {}".format(data, addr))

    async def periodic(self):
        while True:
            await asyncio.sleep(1)
            self.transport.sendto(self.send_data)

loop = asyncio.get_event_loop()

if __name__ == "__main__":
    udp_client = loop.create_datagram_endpoint(
        lambda: UDPClientProtocal(send_data=b'1'),
        remote_addr=('127.0.0.1', 9999),
        local_addr=('127.0.0.1', 42000),
        reuse_port=False
    )
    transport, protocal = loop.run_until_complete(udp_client)
    loop.run_forever()