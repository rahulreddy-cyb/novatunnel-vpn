"""Experimental authenticated DATA framing and per-session replay windows.

This helper is a security-hardening prototype, not a reviewed VPN protocol.
"""
import threading
import time
from novatunnel import crypto
from novatunnel.protocol import PacketType, encode_packet

DOMAIN = b"NovaTunnel-v3-DATA:"
CLIENT_TO_SERVER = b"client-to-server:"
SERVER_TO_CLIENT = b"server-to-client:"
MASK32 = (1 << 32) - 1


class ReplayWindow:
    """Window for a single inbound direction and a single session key."""

    def __init__(self, width=64):
        if width < 1:
            raise ValueError("Replay window must be positive")
        self.width = width
        self.highest = 0
        self.seen = 0
        self.lock = threading.Lock()

    def accept_authenticated(self, seq):
        """Mark a sequence only AFTER successful AEAD verification."""
        if not 1 <= seq <= MASK32:
            return False
        with self.lock:
            if self.highest == 0:
                self.highest = seq
                self.seen = 1
                return True
            if seq > self.highest:
                shift = seq - self.highest
                self.seen = ((self.seen << shift) | 1) & ((1 << self.width) - 1)
                self.highest = seq
                return True
            distance = self.highest - seq
            if distance >= self.width:
                return False
            mask = 1 << distance
            if self.seen & mask:
                return False
            self.seen |= mask
            return True


def _aad(header, direction):
    if direction not in (CLIENT_TO_SERVER, SERVER_TO_CLIENT):
        raise ValueError("Invalid authenticated direction")
    return DOMAIN + direction + header


def seal_data_packet(key, session_id, seq_num, raw_ip_packet, direction):
    if not 1 <= seq_num <= MASK32:
        raise ValueError("DATA sequence out of range; rekey required before wrap")
    # Use the exact serialized header bytes as authenticated associated data.
    header = encode_packet(PacketType.DATA, session_id, seq_num,
                           timestamp=int(time.time()))
    ciphertext = crypto.encrypt(key, raw_ip_packet, associated_data=_aad(header, direction))
    return header + ciphertext


def open_data_packet(key, packet, direction):
    if packet.packet_type != PacketType.DATA:
        raise ValueError("Expected DATA packet")
    # Recreate the exact 16-byte wire header, including all fields.
    header = encode_packet(PacketType.DATA, packet.session_id, packet.seq_num,
                           timestamp=packet.timestamp, flags=packet.flags)
    return crypto.decrypt(key, packet.payload, associated_data=_aad(header, direction))
