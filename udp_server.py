import asyncio

loop = asyncio.get_event_loop()

class UDPServerProtocal(asyncio.DatagramProtocol):

    def __init__(self):
        self.transport = None

    def connection_made(self, transport):
        print("connectin made")
        self.transport = transport

    def datagram_received(self, data, addr):
        print("receive data {} from {}".format(data, addr))
        self.transport.sendto(data, addr)

    def error_received(self, exc):
        pass

    def connection_lost(self, exc):
        self.transport.close()

if __name__ == "__main__":
    udp_server = loop.create_datagram_endpoint(UDPServerProtocal,
                                  local_addr=('127.0.0.1', 9999))
    transport, protocal = loop.run_until_complete(udp_server)
    loop.run_forever()
