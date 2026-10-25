import asyncio

from novatunnel.client import client_tun_reader_loop


class FakeTun:
    name = "ntunc0"

    def __init__(self, packets):
        self.packets = list(packets)
        self.drained = asyncio.Event()

    async def read_async(self, size):
        if self.packets:
            packet = self.packets.pop(0)
            if not self.packets:
                self.drained.set()
            return packet

        await asyncio.Future()


class FakeProtocol:
    def __init__(self):
        self.sent = []

    def send_data(self, packet):
        self.sent.append(packet)


async def main():
    ipv4 = (
        b"\x45\x00\x00\x14"
        + b"\x00" * 8
        + bytes([10, 8, 0, 2])
        + bytes([10, 8, 0, 1])
    )

    ipv6 = b"\x60" + b"\x00" * 39
    short_packet = b"\x45\x00"

    tun = FakeTun([ipv6, short_packet, ipv4])
    protocol = FakeProtocol()
    stop_event = asyncio.Event()

    task = asyncio.create_task(
        client_tun_reader_loop(tun, protocol, stop_event)
    )

    try:
        await asyncio.wait_for(tun.drained.wait(), timeout=3)
        await asyncio.sleep(0)
    finally:
        stop_event.set()
        task.cancel()
        await asyncio.wait_for(task, timeout=3)

    assert protocol.sent == [ipv4], (
        f"Unexpected forwarded packets: {protocol.sent!r}"
    )

    print("PASS 1: IPv6 packets filtered")
    print("PASS 2: Short packets filtered")
    print("PASS 3: IPv4 packets forwarded")
    print("=== CLIENT IPv4 FILTER TEST COMPLETE ===")


asyncio.run(main())
