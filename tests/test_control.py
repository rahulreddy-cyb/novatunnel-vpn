#!/usr/bin/env python3
"""NovaTunnel Phase 4 simulated authenticated control regressions.

No networking sockets, network routes or TUN devices are created.
Targeted behavior tests only; not an independent security review.
"""
import os
import time
from ip_test_utils import ipv4_packet
from novatunnel import crypto
from novatunnel.client import NovaTunnelClientProtocol, ClientState
from novatunnel.peer import PeerRegistry
from novatunnel.protocol import PacketType, encode_packet, decode_packet
from novatunnel.replay import (seal_control_packet, open_control_packet,
                               seal_data_packet, CLIENT_TO_SERVER, SERVER_TO_CLIENT)
from novatunnel.server import NovaTunnelServerProtocol

class FakeTun:
    def __init__(self): self.writes = []
    def write(self, value): self.writes.append(value)

class FakeTransport:
    def __init__(self): self.sent = []
    def sendto(self, data, addr): self.sent.append((data, addr))

registry = PeerRegistry()
client_priv, client_pub = crypto.generate_keypair()
peer = registry.add_peer(name='control-test-peer', public_key_hex=client_pub.hex(),
                         assigned_ip='10.8.0.2')
peer.session_id = 34567
peer.session_key_hex = os.urandom(32).hex()
peer.is_connected = True
peer.endpoint_ip = '127.0.0.1'
peer.endpoint_port = 50000
peer.last_seen = 0
registry.update_peer(peer)
key = bytes.fromhex(peer.session_key_hex)
server = NovaTunnelServerProtocol(registry, FakeTun(), '10.8.0.1', '10.8.0.0/24', [])
server.transport = FakeTransport()
client = NovaTunnelClientProtocol('127.0.0.1', 51820, client_priv, client_pub, FakeTun())
client.transport = FakeTransport()
client.state = ClientState.CONNECTED
client.session_id = peer.session_id
client.session_key = key
client.last_packet_time = 0
addr = ('127.0.0.1', 51000)
server_addr = ('127.0.0.1', 51820)

def forged(ptype, seq=1):
    return encode_packet(ptype, peer.session_id, seq, payload=b'')

# 1–2: Old unauthenticated messages must not change peer state or trigger response.
server.datagram_received(forged(PacketType.KEEPALIVE), addr)
assert peer.endpoint_port == 50000 and peer.last_seen == 0
assert not server.transport.sent
print('PASS: Forged KEEPALIVE cannot update server peer or send acknowledgement')
server.datagram_received(forged(PacketType.DISCONNECT), addr)
assert peer.is_connected and peer.session_id == 34567 and peer.session_key_hex
print('PASS: Forged DISCONNECT cannot terminate server peer')

# 3–4: Client also requires authentication of server control.
client.datagram_received(forged(PacketType.KEEPALIVE), server_addr)
assert client.last_packet_time == 0
client.datagram_received(forged(PacketType.DISCONNECT), server_addr)
assert client.state == ClientState.CONNECTED
print('PASS: Forged server control cannot refresh or disconnect client')

# 5: Legitimate keepalive round-trip, no actual socket activity.
client.send_keepalive()
assert len(client.transport.sent) == 1
valid_ping = client.transport.sent[-1][0]
assert decode_packet(valid_ping).packet_type == PacketType.KEEPALIVE
assert decode_packet(valid_ping).payload
server.datagram_received(valid_ping, addr)
assert peer.endpoint_port == 51000 and peer.last_seen > 0
assert len(server.transport.sent) == 1
ack = server.transport.sent[-1][0]
client.datagram_received(ack, server_addr)
assert client.last_packet_time > 0
print('PASS: Authenticated client keepalive and server acknowledgement interoperate')

# 6: Replay on the server must not refresh peer state or send an ack.
peer.last_seen = 456.0
server.datagram_received(valid_ping, ('127.0.0.1', 52000))
assert peer.last_seen == 456.0 and peer.endpoint_port == 51000
assert len(server.transport.sent) == 1
print('PASS: Replayed client KEEPALIVE cannot refresh or move endpoint')

# 7: Replayed server ACK ignored.
client.last_packet_time = 789.0
client.datagram_received(ack, server_addr)
assert client.last_packet_time == 789.0
print('PASS: Replayed server KEEPALIVE acknowledgement ignored')

# 8: Type/sequence/flags/timestamp modifications are bound into the tag.
ping = seal_control_packet(key, PacketType.KEEPALIVE, peer.session_id, 20, CLIENT_TO_SERVER)
for offset in (0, 8, 9, 13):
    altered = bytearray(ping)
    altered[offset] ^= 1
    server.datagram_received(bytes(altered), addr)
    assert peer.is_connected and peer.last_seen == 456.0
print('PASS: Type, sequence, timestamp and flag tampering rejected')

# 9: Invalid tag with huge seq cannot poison replay tracking.
poison = bytearray(seal_control_packet(key, PacketType.KEEPALIVE, peer.session_id, 0xfffffffe, CLIENT_TO_SERVER))
poison[-1] ^= 1
server.datagram_received(bytes(poison), addr)
valid_later = seal_control_packet(key, PacketType.KEEPALIVE, peer.session_id, 25, CLIENT_TO_SERVER)
server.datagram_received(valid_later, addr)
assert peer.last_seen != 456.0
assert len(server.transport.sent) == 2
print('PASS: Invalid-tag control does not advance replay window')

# 10: Same sequence across DATA and control must be rejected.
server.datagram_received(seal_data_packet(key, peer.session_id, 40, ipv4_packet('10.8.0.2', '10.8.0.1', b'ip'), CLIENT_TO_SERVER), addr)
assert server.tun.writes[-1] == ipv4_packet('10.8.0.2', '10.8.0.1', b'ip')
previous_sent = len(server.transport.sent)
peer.last_seen = 910.0
server.datagram_received(seal_control_packet(key, PacketType.KEEPALIVE, peer.session_id, 40, CLIENT_TO_SERVER), addr)
assert peer.last_seen == 910.0 and len(server.transport.sent) == previous_sent
print('PASS: DATA and control share replay sequence window')

# 11: A control packet must contain no plaintext body.
from novatunnel.replay import CONTROL_DOMAIN
header = encode_packet(PacketType.KEEPALIVE, peer.session_id, 41)
control_data = crypto.encrypt(key, b'bad-body', associated_data=CONTROL_DOMAIN + CLIENT_TO_SERVER + header)
server.datagram_received(header + control_data, addr)
assert peer.last_seen == 910.0
print('PASS: Authenticated but nonempty control payload rejected')

# 12: Direction binding prevents reflection to the client.
client.datagram_received(valid_ping, server_addr)
assert client.last_packet_time == 789.0
print('PASS: Reflected client control packet rejected by client')

# 13: Client emits authenticated disconnect, server accepts then tears down.
client.seq_num = 42
client.send_disconnect()
bye = client.transport.sent[-1][0]
assert decode_packet(bye).packet_type == PacketType.DISCONNECT
server.datagram_received(bye, addr)
assert not peer.is_connected and peer.session_id == 0 and peer.session_key_hex == ''
server.datagram_received(bye, addr)
assert peer.session_id == 0
print('PASS: Authenticated disconnect terminates session; repeat has no effect')

# 14: Independently simulate a legitimate authenticated server disconnect.
client_disconnect = seal_control_packet(key, PacketType.DISCONNECT, client.session_id, 60, SERVER_TO_CLIENT)
client.datagram_received(client_disconnect, server_addr)
assert client.state == ClientState.DISCONNECTED and client.session_key is None and client.session_id == 0
print('PASS: Authenticated server disconnect terminates client session')

# 15: Sequence exhaustion must not wrap.
client.state = ClientState.CONNECTED
client.session_id = 100
client.session_key = key
client.seq_num = 0xffffffff
before = len(client.transport.sent)
client.send_keepalive()
assert len(client.transport.sent) == before
print('PASS: Control sequence exhaustion does not wrap or send')
print('=== CONTROL MESSAGE SECURITY TESTS COMPLETE ===')
