"""
NovaTunnel VPN - Cryptographic Engine
Implements X25519 ECDH key exchange and ChaCha20-Poly1305 authenticated encryption.
"""

import os
import secrets
import struct
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidSignature, InvalidTag


# Salt and info context strings for HKDF derivation
HKDF_SALT = b"NovaTunnel-v1-Salt-KeyDerivation"
HKDF_INFO = b"NovaTunnel-v1-ChaCha20Poly1305-SessionKey"
NONCE_LENGTH = 12
KEY_LENGTH = 32


def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Generate an ephemeral or static X25519 keypair.
    
    Returns:
        Tuple of (private_key_bytes, public_key_bytes), each 32 bytes.
    """
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    private_bytes = private_key.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    return private_bytes, public_bytes


def derive_shared_secret(private_key_bytes: bytes, peer_public_key_bytes: bytes) -> bytes:
    """
    Perform X25519 ECDH exchange and derive a 32-byte symmetric key via HKDF-SHA256.
    
    Args:
        private_key_bytes: 32-byte local private key.
        peer_public_key_bytes: 32-byte remote public key.
        
    Returns:
        32-byte derived session key suitable for ChaCha20-Poly1305.
    """
    if len(private_key_bytes) != KEY_LENGTH:
        raise ValueError(f"Private key must be {KEY_LENGTH} bytes, got {len(private_key_bytes)}")
    if len(peer_public_key_bytes) != KEY_LENGTH:
        raise ValueError(f"Peer public key must be {KEY_LENGTH} bytes, got {len(peer_public_key_bytes)}")
        
    private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)
    peer_public = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
    
    raw_shared_secret = private_key.exchange(peer_public)
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=HKDF_SALT,
        info=HKDF_INFO,
    )
    return hkdf.derive(raw_shared_secret)


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    """
    Encrypt plaintext using ChaCha20-Poly1305.
    Prepends a randomly generated 12-byte nonce to the returned ciphertext.
    
    Args:
        key: 32-byte symmetric encryption key.
        plaintext: Raw data bytes to encrypt.
        associated_data: Optional authenticated associated data (AAD).
        
    Returns:
        12-byte nonce concatenated with ciphertext and 16-byte Poly1305 tag.
    """
    if len(key) != KEY_LENGTH:
        raise ValueError(f"Symmetric key must be {KEY_LENGTH} bytes, got {len(key)}")
        
    nonce = os.urandom(NONCE_LENGTH)
    cipher = ChaCha20Poly1305(key)
    ciphertext = cipher.encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext


def decrypt(key: bytes, ciphertext: bytes, associated_data: bytes = b"") -> bytes:
    """
    Decrypt ciphertext using ChaCha20-Poly1305.
    Expects the first 12 bytes of ciphertext to be the nonce.
    
    Args:
        key: 32-byte symmetric encryption key.
        ciphertext: Nonce (12 bytes) + ciphertext + tag.
        associated_data: Optional authenticated associated data (AAD).
        
    Returns:
        Decrypted plaintext bytes.
        
    Raises:
        ValueError: If ciphertext is too short or key is invalid.
        InvalidTag: If integrity authentication fails.
    """
    if len(key) != KEY_LENGTH:
        raise ValueError(f"Symmetric key must be {KEY_LENGTH} bytes, got {len(key)}")
    if len(ciphertext) < NONCE_LENGTH + 16:
        raise ValueError(f"Ciphertext too short ({len(ciphertext)} bytes); minimum is {NONCE_LENGTH + 16}")
        
    nonce = ciphertext[:NONCE_LENGTH]
    raw_ciphertext = ciphertext[NONCE_LENGTH:]
    
    cipher = ChaCha20Poly1305(key)
    return cipher.decrypt(nonce, raw_ciphertext, associated_data)


def key_to_hex(key: bytes) -> str:
    """Convert raw key bytes to hexadecimal string."""
    return key.hex()


def hex_to_key(hex_str: str) -> bytes:
    """Convert hexadecimal string to raw key bytes."""
    clean_hex = hex_str.strip().replace(" ", "").replace("\n", "")
    return bytes.fromhex(clean_hex)


def generate_session_id() -> int:
    """
    Generate a non-zero random uint32 session identifier.
    
    Returns:
        Integer in range [1, 0xFFFFFFFF].
    """
    # Guarantee non-zero uint32
    return secrets.randbelow(0xFFFFFFFE) + 1
