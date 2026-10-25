"""
NovaTunnel VPN - Client Engine
Handles client connection lifecycle, X25519 handshake, TUN configuration,
system routing redirection, ChaCha20-Poly1305 encryption, and keepalive management.
"""

import asyncio
import enum
import json
import hmac
import hashlib
import struct
import os
import logging
import signal
import socket
import sys
import threading
import time
from typing import Optional, Tuple

from novatunnel import crypto
from novatunnel.config import load_client_config
from novatunnel.protocol import (
    HEADER_SIZE,
    PacketType,
    decode_packet,
    encode_packet,
    ProtocolError,
)
from novatunnel.tun import TunInterface
from novatunnel.utils import (
    format_bytes,
    format_uptime,
    setup_client_routes,
    setup_logging,
    teardown_client_routes,
)

logger = logging.getLogger("novatunnel.client")


class ClientState(enum.Enum):
    DISCONNECTED = "DISCONNECTED"
    CONNECTING = "CONNECTING"
    HANDSHAKING = "HANDSHAKING"
    CONNECTED = "CONNECTED"


class NovaTunnelClientProtocol(asyncio.DatagramProtocol):
    """UDP Datagram Protocol for the client side of NovaTunnel."""

    def __init__(
        self,
        server_host: str,
        server_port: int,
        client_priv_bytes: bytes,
        client_pub_bytes: bytes,
        tun: TunInterface,
        expected_server_public_key: bytes = None,
    ):
        self.server_host = server_host
        self.server_port = server_port
        self.client_priv_bytes = client_priv_bytes
        self.client_pub_bytes = client_pub_bytes
        self.tun = tun
        self.expected_server_public_key = expected_server_public_key
        self.handshake_nonce = None

        self.transport: Optional[asyncio.DatagramTransport] = None
        self.state = ClientState.DISCONNECTED
        self.session_id: int = 0
        self.session_key: Optional[bytes] = None
        self.assigned_ip: Optional[str] = None
        self.server_vpn_ip: Optional[str] = None
        self.vpn_subnet: str = "10.8.0.0/24"
        self.dns_servers: list = []
        self.mtu: int = 1420

        self.seq_num: int = 0
        self.bytes_sent: int = 0
        self.bytes_recv: int = 0
        self.last_packet_time: float = 0.0
        self.handshake_future: Optional[asyncio.Future] = None
        self._lock = threading.Lock()

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport
        logger.debug("Client UDP socket bound successfully.")

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        """Handle incoming packets from the VPN server."""
        try:
            packet = decode_packet(data)
        except Exception as e:
            logger.debug("Received invalid datagram from server: %s", e)
            return

        ptype = packet.packet_type

        if ptype == PacketType.HANDSHAKE_RESP:
            self._handle_handshake_resp(packet, addr)
        elif ptype == PacketType.DATA:
            self._handle_data(packet)
        elif ptype == PacketType.KEEPALIVE:
            self.last_packet_time = time.time()
            logger.debug("Received KEEPALIVE ack from server")
        elif ptype == PacketType.DISCONNECT:
            logger.warning("Received DISCONNECT signal from server")
            self.state = ClientState.DISCONNECTED

    def _handle_handshake_resp(self, packet, addr: tuple) -> None:
        """Process server handshake response and establish encrypted tunnel."""
        if self.state != ClientState.HANDSHAKING:
            return
        if not self.expected_server_public_key or len(self.expected_server_public_key) != 32:
            logger.error("Trusted server public key is not configured; rejecting handshake")
            return
        if self.handshake_nonce is None:
            logger.warning("No active handshake challenge; ignoring response")
            return
        if len(packet.payload) < 32 + 12 + 16 + 32:
            logger.error("HANDSHAKE_RESP payload too short (%d bytes)", len(packet.payload))
            return

        server_pub_bytes = packet.payload[:32]
        encrypted_config = packet.payload[32:-32]
        received_auth_tag = packet.payload[-32:]

        # Authenticate server's configured static identity before trusting its
        # ephemeral key or any configuration in the response.
        auth_key = crypto.derive_server_auth_key(
            self.client_priv_bytes, self.expected_server_public_key
        )
        signed_part = (b"NovaTunnel-v2-HANDSHAKE_RESP" + self.handshake_nonce +
                       struct.pack("!I", packet.session_id) +
                       server_pub_bytes + encrypted_config)
        expected_auth_tag = hmac.new(auth_key, signed_part, hashlib.sha256).digest()
        if not hmac.compare_digest(received_auth_tag, expected_auth_tag):
            logger.warning("Rejected response: server identity verification failed")
            return

        try:
            # 1. Derive shared secret via ECDH
            shared_secret = crypto.derive_shared_secret(self.client_priv_bytes, server_pub_bytes)
            
            # 2. Decrypt configuration payload
            decrypted_json = crypto.decrypt(shared_secret, encrypted_config)
            config_data = json.loads(decrypted_json.decode("utf-8"))

            self.session_id = packet.session_id
            self.session_key = shared_secret
            self.assigned_ip = config_data.get("assigned_ip")
            self.server_vpn_ip = config_data.get("server_vpn_ip")
            self.vpn_subnet = config_data.get("subnet", "10.8.0.0/24")
            self.dns_servers = config_data.get("dns", [])
            self.mtu = int(config_data.get("mtu", 1420))
            self.state = ClientState.CONNECTED
            self.handshake_nonce = None
            self.last_packet_time = time.time()

            logger.info("Tunnel negotiated! Assigned IP: %s | Server VPN IP: %s", self.assigned_ip, self.server_vpn_ip)

            if self.handshake_future and not self.handshake_future.done():
                self.handshake_future.set_result(True)
        except Exception as e:
            logger.error("Failed to process HANDSHAKE_RESP: %s", e)
            if self.handshake_future and not self.handshake_future.done():
                self.handshake_future.set_exception(e)

    def _handle_data(self, packet) -> None:
        """Decrypt incoming IP packet from server and inject into local TUN interface."""
        if self.state != ClientState.CONNECTED or not self.session_key:
            return

        if packet.session_id != self.session_id:
            logger.debug("Mismatch in session_id (got %d, expected %d)", packet.session_id, self.session_id)
            return

        try:
            ip_packet = crypto.decrypt(self.session_key, packet.payload)
            self.bytes_recv += len(packet.payload)
            self.last_packet_time = time.time()
            self.tun.write(ip_packet)
        except Exception as e:
            logger.warning("Decryption of server DATA packet failed: %s", e)

    def send_handshake_init(self) -> None:
        """Send HANDSHAKE_INIT datagram to server containing client's public key."""
        with self._lock:
            self.seq_num += 1
            seq = self.seq_num

        self.handshake_nonce = os.urandom(16)
        packet = encode_packet(
            ptype=PacketType.HANDSHAKE_INIT,
            session_id=0,
            seq_num=seq,
            payload=self.client_pub_bytes + self.handshake_nonce,
        )
        if self.transport:
            self.transport.sendto(packet, (self.server_host, self.server_port))
            logger.debug("Dispatched HANDSHAKE_INIT to %s:%d", self.server_host, self.server_port)

    def send_data(self, raw_ip_packet: bytes) -> None:
        """Encrypt and encapsulate an outbound raw IP packet."""
        if self.state != ClientState.CONNECTED or not self.session_key:
            return

        try:
            encrypted_payload = crypto.encrypt(self.session_key, raw_ip_packet)

            with self._lock:
                self.seq_num += 1
                seq = self.seq_num

            packet = encode_packet(
                ptype=PacketType.DATA,
                session_id=self.session_id,
                seq_num=seq,
                payload=encrypted_payload,
            )

            if self.transport:
                self.transport.sendto(packet, (self.server_host, self.server_port))
                self.bytes_sent += len(packet)
        except Exception as e:
            logger.error("Failed to send DATA packet to server: %s", e)

    def send_keepalive(self) -> None:
        """Dispatch periodic KEEPALIVE datagram to keep NAT binding active."""
        if self.state != ClientState.CONNECTED:
            return

        with self._lock:
            self.seq_num += 1
            seq = self.seq_num

        packet = encode_packet(
            ptype=PacketType.KEEPALIVE,
            session_id=self.session_id,
            seq_num=seq,
            payload=b"",
        )
        if self.transport:
            self.transport.sendto(packet, (self.server_host, self.server_port))
            logger.debug("Dispatched KEEPALIVE packet")

    def send_disconnect(self) -> None:
        """Notify server of impending graceful shutdown."""
        if self.state != ClientState.CONNECTED:
            return

        with self._lock:
            self.seq_num += 1
            seq = self.seq_num

        packet = encode_packet(
            ptype=PacketType.DISCONNECT,
            session_id=self.session_id,
            seq_num=seq,
            payload=b"",
        )
        if self.transport:
            self.transport.sendto(packet, (self.server_host, self.server_port))
            logger.info("Dispatched DISCONNECT packet to server")


async def client_tun_reader_loop(
    tun: TunInterface,
    protocol: NovaTunnelClientProtocol,
    stop_event: asyncio.Event,
) -> None:
    """Read outgoing IP packets from local TUN interface and encapsulate them to server."""
    loop = asyncio.get_running_loop()
    logger.info("Client TUN reader loop started on %s", tun.name)

    while not stop_event.is_set():
        try:
            raw_packet = await loop.run_in_executor(None, tun.read, 2048)
            if not raw_packet or len(raw_packet) < 20:
                continue
            protocol.send_data(raw_packet)
        except asyncio.CancelledError:
            break
        except Exception as e:
            if not stop_event.is_set():
                logger.error("Error in client TUN reader: %s", e)
                await asyncio.sleep(0.01)


async def client_keepalive_loop(
    protocol: NovaTunnelClientProtocol,
    interval: int,
    stop_event: asyncio.Event,
) -> None:
    """Send periodic keepalives to prevent NAT expiration and maintain session."""
    logger.info("Keepalive loop active (interval=%ds)", interval)
    while not stop_event.is_set():
        try:
            await asyncio.sleep(interval)
            if protocol.state == ClientState.CONNECTED:
                protocol.send_keepalive()
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.debug("Keepalive exception: %s", e)


async def run_client(config_dict: Optional[dict] = None) -> None:
    """Main entry point to run the NovaTunnel VPN client."""
    config = config_dict or load_client_config()
    client_cfg = config["client"]

    setup_logging()
    logger.info("Starting NovaTunnel VPN Client...")

    server_host = client_cfg.get("server_host", "127.0.0.1")
    server_port = int(client_cfg.get("server_port", 51820))
    tun_name = client_cfg.get("tun_name", "nova-client")
    keepalive_interval = int(client_cfg.get("keepalive_interval", 25))
    route_all = bool(client_cfg.get("route_all_traffic", True))

    # Resolve server IP if hostname provided
    try:
        server_ip = socket.gethostbyname(server_host)
    except socket.gaierror:
        server_ip = server_host

    # Key management: use configured private key or generate ephemeral keypair
    priv_hex = client_cfg.get("private_key", "").strip()
    if priv_hex:
        priv_bytes = crypto.hex_to_key(priv_hex)
        from cryptography.hazmat.primitives.asymmetric import x25519
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        priv_obj = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
        pub_bytes = priv_obj.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    else:
        priv_bytes, pub_bytes = crypto.generate_keypair()
        logger.info("Generated ephemeral client keypair")

    server_pub_hex = str(client_cfg.get("server_public_key", "")).strip()
    try:
        expected_server_public_key = bytes.fromhex(server_pub_hex)
        if len(expected_server_public_key) != 32:
            raise ValueError("server public key must be 32 bytes")
    except (ValueError, TypeError) as e:
        raise ValueError("Configure a valid client.server_public_key before connecting") from e

    tun = TunInterface(name=tun_name)
    try:
        tun.open()
    except NotImplementedError as e:
        logger.warning("TUN device warning: %s", e)
    except Exception as e:
        logger.error("Could not open TUN device: %s", e)
        raise

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    # Create UDP transport
    connect_coro = loop.create_datagram_endpoint(
        lambda: NovaTunnelClientProtocol(
            server_host=server_host,
            server_port=server_port,
            client_priv_bytes=priv_bytes,
            client_pub_bytes=pub_bytes,
            tun=tun,
            expected_server_public_key=expected_server_public_key,
        ),
        local_addr=("0.0.0.0", 0),
    )
    transport, protocol = await connect_coro

    # Perform handshake with retry logic
    protocol.state = ClientState.HANDSHAKING
    handshake_success = False
    max_retries = 5

    for attempt in range(1, max_retries + 1):
        logger.info("Initiating handshake with %s:%d (attempt %d/%d)...", server_host, server_port, attempt, max_retries)
        protocol.handshake_future = loop.create_future()
        protocol.send_handshake_init()

        try:
            await asyncio.wait_for(protocol.handshake_future, timeout=4.0)
            handshake_success = True
            break
        except asyncio.TimeoutError:
            logger.warning("Handshake attempt %d timed out", attempt)
        except Exception as e:
            logger.error("Handshake attempt %d failed: %s", attempt, e)

    if not handshake_success:
        logger.error("Failed to establish handshake with NovaTunnel server after %d attempts", max_retries)
        tun.close()
        transport.close()
        return

    # Configure TUN interface with assigned parameters
    if tun.is_open and protocol.assigned_ip and protocol.server_vpn_ip:
        tun.configure(
            local_ip=protocol.assigned_ip,
            peer_ip=protocol.server_vpn_ip,
            mtu=protocol.mtu,
        )
        tun.up()

    # Configure client routing tables
    routes_state = setup_client_routes(
        server_ip=server_ip,
        tun_name=tun.name,
        server_vpn_ip=protocol.server_vpn_ip or "10.8.0.1",
        vpn_subnet=protocol.vpn_subnet,
        route_all=route_all,
    )

    # Spawn background tasks
    tasks = []
    if tun.is_open:
        tasks.append(asyncio.create_task(client_tun_reader_loop(tun, protocol, stop_event)))
    tasks.append(asyncio.create_task(client_keepalive_loop(protocol, keepalive_interval, stop_event)))

    def shutdown():
        logger.info("Disconnecting client...")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, shutdown)
        except NotImplementedError:
            pass

    start_time = time.time()
    try:
        logger.info("Connected to NovaTunnel VPN. Traffic is now encrypted.")
        await stop_event.wait()
    finally:
        logger.info("Terminating client connection...")
        stop_event.set()
        protocol.send_disconnect()

        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

        if routes_state:
            orig_gw, orig_dev = routes_state
            teardown_client_routes(
                server_ip=server_ip,
                tun_name=tun.name,
                orig_gw=orig_gw,
                orig_dev=orig_dev,
                vpn_subnet=protocol.vpn_subnet,
                route_all=route_all,
            )

        tun.close()
        transport.close()
        logger.info(
            "Session summary: Uptime: %s | Sent: %s | Recv: %s",
            format_uptime(time.time() - start_time),
            format_bytes(protocol.bytes_sent),
            format_bytes(protocol.bytes_recv),
        )
