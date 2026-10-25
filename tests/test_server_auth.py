#!/usr/bin/env python3
"""Simulated authenticated server handshake regression tests for NovaTunnel v2 prototype."""
import json
from novatunnel import crypto
from novatunnel.client import NovaTunnelClientProtocol, ClientState
from novatunnel.peer import PeerRegistry
from novatunnel.protocol import PacketType, encode_packet, decode_packet
from novatunnel.server import NovaTunnelServerProtocol

class FakeTransport:
    def __init__(self):
        self.sent = []
    def sendto(self, data, addr):
        self.sent.append((data, addr))

server_priv, server_pub = crypto.generate_keypair()
client_priv, client_pub = crypto.generate_keypair()
attacker_priv, attacker_pub = crypto.generate_keypair()
registry = PeerRegistry()
peer = registry.add_peer(name="authorized", public_key_hex=client_pub.hex(), assigned_ip="10.8.0.2")
server = NovaTunnelServerProtocol(registry, None, "10.8.0.1", "10.8.0.0/24", [], server_private_key=server_priv)
server.transport = FakeTransport()
client = NovaTunnelClientProtocol("127.0.0.1", 51820, client_priv, client_pub, None, expected_server_public_key=server_pub)
client.transport = FakeTransport()
client.state = ClientState.HANDSHAKING
client.send_handshake_init()
hello = client.transport.sent.pop()[0]
server.datagram_received(hello, ("127.0.0.1", 42000))
assert len(server.transport.sent) == 1
response = server.transport.sent.pop()[0]

# Forged unauthenticated server response must not be accepted.
fake_session_key = crypto.derive_shared_secret(attacker_priv, client_pub)
spoofed = encode_packet(PacketType.HANDSHAKE_RESP, 555, 1, attacker_pub + crypto.encrypt(fake_session_key, json.dumps({"assigned_ip":"10.8.0.99"}).encode()) + b"\x00" * 32)
client.datagram_received(spoofed,("127.0.0.1", 51820))
assert client.state == ClientState.HANDSHAKING, "unauthenticated server accepted"
print("PASS: Forged server handshake rejected")

# A tampered authenticated response must be rejected too.
resp_bytes = response
tampered = bytearray(resp_bytes)
tampered[-1] ^= 1
client.datagram_received(bytes(tampered),("127.0.0.1",51820))
assert client.state == ClientState.HANDSHAKING
print("PASS: Modified response rejected")

# Valid server response must connect.
client.datagram_received(resp_bytes,("127.0.0.1",51820))
assert client.state == ClientState.CONNECTED
assert client.assigned_ip == "10.8.0.2"
assert client.session_key.hex() == peer.session_key_hex
print("PASS: Authenticated authorized client connected")
print("PASS: Client-server keys match")

# Replay of previously valid handshake response after new challenge must fail.
client.state = ClientState.HANDSHAKING
client.send_handshake_init()
client.datagram_received(resp_bytes,("127.0.0.1",51820))
assert client.state == ClientState.HANDSHAKING
print("PASS: Stale handshake response rejected")

# Wrong pinned identity rejects valid response.
wrong = NovaTunnelClientProtocol("127.0.0.1", 51820, client_priv, client_pub, None, expected_server_public_key=attacker_pub)
wrong.state = ClientState.HANDSHAKING
wrong.handshake_nonce = client.handshake_nonce  # same outstanding challenge
wrong.datagram_received(resp_bytes,("127.0.0.1",51820))
assert wrong.state == ClientState.HANDSHAKING
print("PASS: Incorrect pinned server identity rejected")
