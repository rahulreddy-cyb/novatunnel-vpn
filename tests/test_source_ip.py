#!/usr/bin/env python3
"""Isolated IPv4 source-address validation regression tests."""

from types import SimpleNamespace

from ip_test_utils import ipv4_packet
from novatunnel.protocol import decode_packet
from novatunnel.replay import seal_data_packet, CLIENT_TO_SERVER
from novatunnel.server import NovaTunnelServerProtocol

key = b"\x13" * 32

peer = SimpleNamespace(
    name="source-ip-test-peer",
    session_id=4242,
    session_key_hex=key.hex(),
    is_connected=True,
    assigned_ip="10.8.0.2",
    endpoint_ip="127.0.0.1",
    endpoint_port=50000,
    last_seen=0,
    bytes_recv=0,
)

class Registry:
    def get_by_session_id(self, sid):
        return peer if sid == peer.session_id else None

class FakeTun:
    def __init__(self):
        self.writes = []

    def write(self, packet):
        self.writes.append(packet)

server = NovaTunnelServerProtocol.__new__(
    NovaTunnelServerProtocol
)
server.registry = Registry()
server.tun = FakeTun()
server.inbound_replay_windows = {}

def send(seq, ip_packet):
    wire = seal_data_packet(
        key, peer.session_id, seq,
        ip_packet, CLIENT_TO_SERVER
    )
    server._handle_data(
        decode_packet(wire),
        ("127.0.0.1", 60000)
    )

valid = ipv4_packet("10.8.0.2", "10.8.0.1", b"hello")
spoofed = ipv4_packet("10.8.0.99", "10.8.0.1", b"hello")

# Reject spoofing without changing connection state.
send(100, spoofed)
assert server.tun.writes == []
assert peer.endpoint_port == 50000
assert peer.bytes_recv == 0
assert server.inbound_replay_windows == {}
print("PASS: Spoofed source IP rejected")

# An invalid packet must not consume its sequence number.
send(100, valid)
assert server.tun.writes == [valid]
assert peer.endpoint_port == 60000
print("PASS: Legitimate source IP accepted")

# The same authenticated DATA packet must not be accepted twice.
send(100, valid)
assert server.tun.writes == [valid]
print("PASS: DATA replay protection preserved")

# Reject truncated packets.
send(101, b"\x45")
assert server.tun.writes == [valid]
print("PASS: Truncated IPv4 packet rejected")

# Reject incorrect packet lengths.
bad_length = bytearray(valid)
bad_length[2:4] = (len(valid) + 1).to_bytes(2, "big")
send(101, bytes(bad_length))
assert server.tun.writes == [valid]
print("PASS: Invalid IPv4 length rejected")

# Reject unsupported IP versions.
send(101, b"\x60" + b"\x00" * 39)
assert server.tun.writes == [valid]
print("PASS: Unsupported IP version rejected")

# Rejected packets must not poison the replay window.
send(101, valid)
assert server.tun.writes == [valid, valid]
print("PASS: Rejected packets do not consume sequence numbers")

print("=== SOURCE-IP SECURITY TESTS COMPLETE ===")
