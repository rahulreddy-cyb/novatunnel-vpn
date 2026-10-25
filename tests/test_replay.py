#!/usr/bin/env python3
"""Targeted simulated NovaTunnel replay, integrity and bidirectional DATA tests.

No VPN socket, route or TUN interface is created. Does not test production security.
"""
import os
from novatunnel.client import NovaTunnelClientProtocol, ClientState
from novatunnel.peer import PeerRegistry
from novatunnel.protocol import PacketType, decode_packet
from novatunnel.server import NovaTunnelServerProtocol
from novatunnel.replay import seal_data_packet, CLIENT_TO_SERVER, SERVER_TO_CLIENT, ReplayWindow
from novatunnel import crypto

from ip_test_utils import ipv4_packet

def client_ip(payload):
    return ipv4_packet("10.8.0.2", "10.8.0.1", payload)

def server_ip(payload):
    return ipv4_packet("10.8.0.1", "10.8.0.2", payload)



class FakeTun:
    def __init__(self): self.writes = []
    def write(self, value): self.writes.append(value)


class FakeTransport:
    def __init__(self): self.sent = []
    def sendto(self, data, addr): self.sent.append((data, addr))


registry = PeerRegistry()
client_priv, client_pub = crypto.generate_keypair()
peer = registry.add_peer(name='replay-test-peer', public_key_hex=client_pub.hex(), assigned_ip='10.8.0.2')
peer.session_id = 12345
peer.session_key_hex = os.urandom(32).hex()
peer.is_connected = True
peer.endpoint_ip = '127.0.0.1'
peer.endpoint_port = 50000
registry.update_peer(peer)
key = bytes.fromhex(peer.session_key_hex)
server_tun = FakeTun()
client_tun = FakeTun()
server = NovaTunnelServerProtocol(registry, server_tun, '10.8.0.1', '10.8.0.0/24', [])
server.transport = FakeTransport()
client = NovaTunnelClientProtocol('127.0.0.1', 51820, client_priv, client_pub, client_tun)
client.transport = FakeTransport()
client.session_id = peer.session_id
client.session_key = key
client.state = ClientState.CONNECTED


def as_client_frame(seq, value):
    return seal_data_packet(key, peer.session_id, seq, value, CLIENT_TO_SERVER)


packet = as_client_frame(100, client_ip(b'first-packet'))
server.datagram_received(packet, ('127.0.0.1', 50000))
assert server_tun.writes == [client_ip(b'first-packet')]
server.datagram_received(packet, ('127.0.0.1', 50000))
assert server_tun.writes == [client_ip(b'first-packet')]
print('PASS: Duplicate client DATA rejected')

# Header is included in AEAD associated data, so tampering with seq fails.
header_tamper = bytearray(packet)
header_tamper[8] ^= 1
server.datagram_received(bytes(header_tamper), ('127.0.0.1', 50000))
assert server_tun.writes == [client_ip(b'first-packet')]
print('PASS: Modified sequence number rejected')

for tamper_at in (9, 13):  # Timestamp and reserved flag bytes.
    altered = bytearray(packet)
    altered[tamper_at] ^= 1
    server.datagram_received(bytes(altered), ('127.0.0.1', 50000))
    assert server_tun.writes == [client_ip(b'first-packet')]
print('PASS: Modified timestamp and flags rejected')

for seq in (102, 101):
    server.datagram_received(as_client_frame(seq, client_ip(bytes([seq]))), ('127.0.0.1', 50000))
assert server_tun.writes == [client_ip(b'first-packet'), client_ip(b'\x66'), client_ip(b'\x65')]
print('PASS: Authenticated out-of-order DATA accepted')

server.datagram_received(as_client_frame(30, client_ip(b'too-old')), ('127.0.0.1', 50000))
assert len(server_tun.writes) == 3
print('PASS: DATA outside replay window rejected')

poison = bytearray(as_client_frame(0xFFFFFFFE, client_ip(b'poison')))
poison[-1] ^= 1
server.datagram_received(bytes(poison), ('127.0.0.1', 50000))
server.datagram_received(as_client_frame(103, client_ip(b'legitimate')), ('127.0.0.1', 50000))
assert server_tun.writes[-1] == client_ip(b'legitimate')
print('PASS: Invalid tag does not advance replay window')

client.seq_num = 103  # Simulate preceding outbound sequence numbers in this session.
client.send_data(client_ip(b'client outbound'))
assert client.transport.sent
client_packet = client.transport.sent[-1][0]
server.datagram_received(client_packet, ('127.0.0.1', 50000))
assert server_tun.writes[-1] == client_ip(b'client outbound')
print('PASS: Client send_data interoperates with server receive DATA')

server.send_data_to_peer(peer, server_ip(b'server outbound'))
assert server.transport.sent
server_packet = server.transport.sent[-1][0]
client.datagram_received(server_packet, ('127.0.0.1', 51820))
assert client_tun.writes == [server_ip(b'server outbound')]
client.datagram_received(server_packet, ('127.0.0.1', 51820))
assert client_tun.writes == [server_ip(b'server outbound')]
print('PASS: Server DATA accepted once; replay rejected by client')

# The same encrypted payload cannot be reflected back at the sender.
client.datagram_received(client_packet, ('127.0.0.1', 51820))
assert client_tun.writes == [server_ip(b'server outbound')]
print('PASS: Directional authentication prevents DATA reflection')

win = ReplayWindow()
assert win.accept_authenticated(0xFFFFFFFF)
assert not win.accept_authenticated(0xFFFFFFFF)
assert not win.accept_authenticated(0)
print('PASS: Sequence wrap and duplicates rejected by replay window')

print('=== DATA REPLAY REGRESSION TESTS COMPLETE ===')
