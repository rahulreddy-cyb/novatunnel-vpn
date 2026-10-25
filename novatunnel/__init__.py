"""
NovaTunnel VPN - Encrypted High-Performance TUN-Based Virtual Private Network
"""

__version__ = "1.0.0"
__author__ = "NovaTunnel Team"

from novatunnel.crypto import (
    generate_keypair,
    derive_shared_secret,
    encrypt,
    decrypt,
    key_to_hex,
    hex_to_key,
    generate_session_id,
)
from novatunnel.protocol import (
    PacketType,
    NovaTunnelPacket,
    encode_packet,
    decode_packet,
)
from novatunnel.peer import Peer, PeerRegistry
from novatunnel.tun import TunInterface
from novatunnel.config import load_server_config, load_client_config, save_config

__all__ = [
    "__version__",
    "generate_keypair",
    "derive_shared_secret",
    "encrypt",
    "decrypt",
    "key_to_hex",
    "hex_to_key",
    "generate_session_id",
    "PacketType",
    "NovaTunnelPacket",
    "encode_packet",
    "decode_packet",
    "Peer",
    "PeerRegistry",
    "TunInterface",
    "load_server_config",
    "load_client_config",
    "save_config",
]
