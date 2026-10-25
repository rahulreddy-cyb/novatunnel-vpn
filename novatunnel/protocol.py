"""
NovaTunnel VPN - Protocol Framing & Packet Serialization
Defines packet types, binary header formatting, and encode/decode routines.
"""

import enum
import struct
import time
from dataclasses import dataclass
from typing import Optional

HEADER_SIZE = 16
MAX_PACKET_SIZE = 65535
HEADER_STRUCT_FORMAT = "!B I I I 3s"


class PacketType(enum.IntEnum):
    """NovaTunnel protocol packet types."""
    HANDSHAKE_INIT = 1
    HANDSHAKE_RESP = 2
    DATA = 3
    KEEPALIVE = 4
    DISCONNECT = 5

    @classmethod
    def has_value(cls, value: int) -> bool:
        return value in cls._value2member_map_


class ProtocolError(Exception):
    """Raised when packet encoding or decoding fails."""
    pass


@dataclass
class NovaTunnelPacket:
    """Represents a decoded NovaTunnel packet."""
    packet_type: PacketType
    session_id: int
    seq_num: int
    timestamp: int
    flags: bytes
    payload: bytes

    @property
    def total_size(self) -> int:
        return HEADER_SIZE + len(self.payload)

    def __repr__(self) -> str:
        return (
            f"<NovaTunnelPacket type={self.packet_type.name}({self.packet_type.value}) "
            f"session_id={self.session_id:#010x} seq={self.seq_num} "
            f"timestamp={self.timestamp} payload_len={len(self.payload)}>"
        )


def encode_packet(
    ptype: PacketType,
    session_id: int,
    seq_num: int,
    payload: bytes = b"",
    timestamp: Optional[int] = None,
    flags: bytes = b"\x00\x00\x00",
) -> bytes:
    """
    Encode header fields and payload into a NovaTunnel binary packet.

    Header (16 bytes):
      [0]     : Packet type (uint8)
      [1:5]   : Session ID (uint32 big-endian)
      [5:9]   : Sequence number (uint32 big-endian)
      [9:13]  : Timestamp (uint32 big-endian, unix seconds)
      [13:16] : Flags (3 bytes reserved, default 0x000000)

    Args:
        ptype: PacketType enum or integer value.
        session_id: uint32 session identifier.
        seq_num: uint32 packet sequence number.
        payload: Binary payload bytes.
        timestamp: Unix epoch timestamp (seconds). Defaults to current time.
        flags: 3-byte reserved field.

    Returns:
        16-byte header + payload as bytes.
    """
    if isinstance(ptype, int) and not isinstance(ptype, PacketType):
        ptype = PacketType(ptype)

    if timestamp is None:
        timestamp = int(time.time())

    if len(flags) != 3:
        flags = flags[:3].ljust(3, b"\x00")

    total_len = HEADER_SIZE + len(payload)
    if total_len > MAX_PACKET_SIZE:
        raise ProtocolError(f"Packet size {total_len} exceeds maximum {MAX_PACKET_SIZE}")

    try:
        header = struct.pack(
            HEADER_STRUCT_FORMAT,
            int(ptype),
            session_id & 0xFFFFFFFF,
            seq_num & 0xFFFFFFFF,
            timestamp & 0xFFFFFFFF,
            flags,
        )
    except struct.error as e:
        raise ProtocolError(f"Failed to pack NovaTunnel header: {e}") from e

    return header + payload


def decode_packet(data: bytes) -> NovaTunnelPacket:
    """
    Decode a binary packet into a NovaTunnelPacket instance.

    Args:
        data: Raw incoming UDP datagram bytes.

    Returns:
        NovaTunnelPacket dataclass instance.

    Raises:
        ProtocolError: If data is shorter than HEADER_SIZE or packet type is invalid.
    """
    if len(data) < HEADER_SIZE:
        raise ProtocolError(
            f"Datagram too short: {len(data)} bytes, expected at least {HEADER_SIZE}"
        )

    if len(data) > MAX_PACKET_SIZE:
        raise ProtocolError(
            f"Datagram exceeds maximum allowed size: {len(data)} > {MAX_PACKET_SIZE}"
        )

    header_bytes = data[:HEADER_SIZE]
    payload = data[HEADER_SIZE:]

    try:
        raw_type, session_id, seq_num, timestamp, flags = struct.unpack(
            HEADER_STRUCT_FORMAT, header_bytes
        )
    except struct.error as e:
        raise ProtocolError(f"Failed to unpack header bytes: {e}") from e

    if not PacketType.has_value(raw_type):
        raise ProtocolError(f"Unknown NovaTunnel packet type: {raw_type}")

    packet_type = PacketType(raw_type)

    return NovaTunnelPacket(
        packet_type=packet_type,
        session_id=session_id,
        seq_num=seq_num,
        timestamp=timestamp,
        flags=flags,
        payload=payload,
    )
