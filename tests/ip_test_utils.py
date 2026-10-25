"""Valid IPv4 packets for NovaTunnel regression tests."""
import ipaddress
import struct


def ipv4_packet(source, destination, payload=b""):
    src = ipaddress.IPv4Address(source).packed
    dst = ipaddress.IPv4Address(destination).packed

    length = 20 + len(payload)
    if length > 65535:
        raise ValueError("IPv4 packet too large")

    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, length, 0, 0, 64, 253, 0,
        src, dst
    )

    total = sum(
        int.from_bytes(header[i:i+2], "big")
        for i in range(0, 20, 2)
    )

    while total >> 16:
        total = (total & 0xffff) + (total >> 16)

    checksum = (~total) & 0xffff
    header = header[:10] + struct.pack("!H", checksum) + header[12:]

    return header + payload
