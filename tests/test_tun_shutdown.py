import asyncio
import os

from novatunnel.tun import TunInterface


async def main():
    read_fd, write_fd = os.pipe()

    tun = TunInterface("test-tun")
    tun.fd = read_fd
    tun.is_open = True

    loop = asyncio.get_running_loop()

    try:
        task = asyncio.create_task(tun.read_async(2048))
        await asyncio.sleep(0)

        os.write(write_fd, b"novatunnel-test")

        result = await asyncio.wait_for(task, timeout=2)
        assert result == b"novatunnel-test"

        print("PASS 1: Asynchronous TUN read works")

        assert loop.remove_reader(read_fd) is False
        print("PASS 2: Reader callback cleaned up")

        task = asyncio.create_task(tun.read_async(2048))
        await asyncio.sleep(0)

        task.cancel()

        try:
            await asyncio.wait_for(task, timeout=2)
        except asyncio.CancelledError:
            pass
        else:
            raise AssertionError("Task cancellation failed")

        print("PASS 3: Pending read cancelled")

        assert loop.remove_reader(read_fd) is False
        print("PASS 4: Cancelled reader callback cleaned up")

    finally:
        tun.fd = None
        tun.is_open = False
        os.close(read_fd)
        os.close(write_fd)


asyncio.run(main())

print("=== TUN SHUTDOWN REGRESSION TESTS COMPLETE ===")
