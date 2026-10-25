"""
NovaTunnel VPN - High-Performance Async VPN Server
Handles UDP packet routing, X25519 handshake negotiation, ChaCha20-Poly1305 encryption,
peer registry management, TUN interface I/O, and dashboard integration.
"""

import asyncio
import json
import logging
import os
import signal
import socket
import threading
import time
from typing import Optional, Set

from novatunnel import crypto
from novatunnel.config import load_server_config
from novatunnel.peer import Peer, PeerRegistry
from novatunnel.protocol import (
    HEADER_SIZE,
    PacketType,
    decode_packet,
    encode_packet,
    ProtocolError,
)
from novatunnel.tun import TunInterface
from novatunnel.utils import (
    get_default_interface,
    setup_logging,
    setup_nat,
    teardown_nat,
)

logger = logging.getLogger("novatunnel.server")


class NovaTunnelServerProtocol(asyncio.DatagramProtocol):
    """Async UDP Datagram Protocol handling NovaTunnel VPN framing and crypto."""

    def __init__(
        self,
        registry: PeerRegistry,
        tun: TunInterface,
        server_vpn_ip: str,
        vpn_subnet: str,
        dns_servers: list,
        mtu: int = 1420,
    ):
        self.registry = registry
        self.tun = tun
        self.server_vpn_ip = server_vpn_ip
        self.vpn_subnet = vpn_subnet
        self.dns_servers = dns_servers
        self.mtu = mtu
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.seq_counter: int = 0
        self._lock = threading.Lock()

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport
        sock = transport.get_extra_info("socket")
        addr = sock.getsockname() if sock else ("0.0.0.0", 0)
        logger.info("NovaTunnel UDP Server listening on %s:%d", addr[0], addr[1])

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        """Handle incoming UDP datagram from client."""
        try:
            packet = decode_packet(data)
        except ProtocolError as e:
            logger.debug("Received malformed packet from %s: %s", addr, e)
            return
        except Exception as e:
            logger.warning("Error decoding datagram from %s: %s", addr, e)
            return

        ptype = packet.packet_type

        if ptype == PacketType.HANDSHAKE_INIT:
            self._handle_handshake_init(packet, addr)
        elif ptype == PacketType.DATA:
            self._handle_data(packet, addr)
        elif ptype == PacketType.KEEPALIVE:
            self._handle_keepalive(packet, addr)
        elif ptype == PacketType.DISCONNECT:
            self._handle_disconnect(packet, addr)
        else:
            logger.debug("Unhandled packet type %s from %s", ptype, addr)

    def _handle_handshake_init(self, packet, addr: tuple) -> None:
        """Process client handshake initiation and reply with server credentials."""
        if len(packet.payload) < 32:
            logger.warning("Handshake payload too short from %s (%d bytes)", addr, len(packet.payload))
            return

        client_pub_bytes = packet.payload[:32]
        client_pub_hex = client_pub_bytes.hex()
        logger.info("Received HANDSHAKE_INIT from %s (client pub: %s...)", addr, client_pub_hex[:16])

        # 1. Lookup peer in registry or create an entry
        peer = self.registry.get_by_public_key(client_pub_hex)
        if not peer:
            # Automatic peer registration if space permits
            try:
                assigned_ip = self.registry.allocate_ip(subnet=self.vpn_subnet)
                peer_name = f"peer-{client_pub_hex[:8]}"
                peer = self.registry.add_peer(
                    name=peer_name,
                    public_key_hex=client_pub_hex,
                    assigned_ip=assigned_ip,
                    subnet=self.vpn_subnet,
                )
                logger.info("Auto-registered new peer '%s' with IP %s", peer_name, assigned_ip)
            except Exception as e:
                logger.error("Failed to allocate IP for incoming peer %s: %s", addr, e)
                return

        # 2. Generate server's ephemeral keypair for this session
        server_priv, server_pub = crypto.generate_keypair()

        # 3. Derive shared secret via X25519 ECDH + HKDF
        shared_secret = crypto.derive_shared_secret(server_priv, client_pub_bytes)

        # 4. Generate random uint32 session identifier
        session_id = crypto.generate_session_id()

        # 5. Update peer record with active session info
        peer.session_id = session_id
        peer.session_key_hex = shared_secret.hex()
        peer.endpoint_ip = addr[0]
        peer.endpoint_port = addr[1]
        peer.is_connected = True
        peer.last_seen = time.time()
        self.registry.update_peer(peer)

        # 6. Prepare response payload (JSON configuration)
        response_payload_data = {
            "assigned_ip": peer.assigned_ip,
            "server_vpn_ip": self.server_vpn_ip,
            "subnet": self.vpn_subnet,
            "dns": self.dns_servers,
            "session_id": session_id,
            "mtu": self.mtu,
        }
        json_bytes = json.dumps(response_payload_data).encode("utf-8")

        # 7. Encrypt response payload with derived shared secret
        encrypted_config = crypto.encrypt(shared_secret, json_bytes)

        # 8. Frame response: server public key (32 bytes) + encrypted config
        resp_payload = server_pub + encrypted_config
        with self._lock:
            self.seq_counter += 1
            seq = self.seq_counter

        resp_packet = encode_packet(
            ptype=PacketType.HANDSHAKE_RESP,
            session_id=session_id,
            seq_num=seq,
            payload=resp_payload,
        )

        if self.transport:
            self.transport.sendto(resp_packet, addr)
            logger.info("Sent HANDSHAKE_RESP to %s for peer %s (assigned IP: %s)", addr, peer.name, peer.assigned_ip)

    def _handle_data(self, packet, addr: tuple) -> None:
        """Process encapsulated IP data packet from client."""
        peer = self.registry.get_by_session_id(packet.session_id)
        if not peer or not peer.is_connected or not peer.session_key_hex:
            logger.debug("Received DATA packet with invalid or expired session_id %s from %s", packet.session_id, addr)
            return

        session_key = bytes.fromhex(peer.session_key_hex)
        try:
            ip_packet = crypto.decrypt(session_key, packet.payload)
        except Exception as e:
            logger.warning("Decryption failed for peer %s (%s): %s", peer.name, addr, e)
            return

        # Update peer statistics and endpoint (handles dynamic NAT / IP roaming)
        peer.endpoint_ip = addr[0]
        peer.endpoint_port = addr[1]
        peer.last_seen = time.time()
        peer.bytes_recv += len(packet.payload)

        # Inject decrypted IP packet into the Linux virtual network stack
        try:
            self.tun.write(ip_packet)
        except Exception as e:
            logger.error("Failed to write packet to TUN interface: %s", e)

    def _handle_keepalive(self, packet, addr: tuple) -> None:
        """Process keepalive packet from client and respond."""
        peer = self.registry.get_by_session_id(packet.session_id)
        if peer:
            peer.last_seen = time.time()
            peer.endpoint_ip = addr[0]
            peer.endpoint_port = addr[1]
            peer.is_connected = True

            with self._lock:
                self.seq_counter += 1
                seq = self.seq_counter

            resp = encode_packet(
                ptype=PacketType.KEEPALIVE,
                session_id=packet.session_id,
                seq_num=seq,
                payload=b"",
            )
            if self.transport:
                self.transport.sendto(resp, addr)

    def _handle_disconnect(self, packet, addr: tuple) -> None:
        """Handle client disconnection notification."""
        peer = self.registry.get_by_session_id(packet.session_id)
        if peer:
            peer.is_connected = False
            peer.session_id = 0
            peer.session_key_hex = ""
            logger.info("Peer '%s' (%s) gracefully disconnected", peer.name, addr)

    def send_data_to_peer(self, peer: Peer, raw_ip_packet: bytes) -> None:
        """Encrypt and dispatch an IP packet to a specific connected peer."""
        if not peer.is_connected or not peer.session_key_hex or not peer.endpoint_ip or not peer.endpoint_port:
            return

        try:
            session_key = bytes.fromhex(peer.session_key_hex)
            encrypted_payload = crypto.encrypt(session_key, raw_ip_packet)

            with self._lock:
                self.seq_counter += 1
                seq = self.seq_counter

            data_packet = encode_packet(
                ptype=PacketType.DATA,
                session_id=peer.session_id,
                seq_num=seq,
                payload=encrypted_payload,
            )

            if self.transport:
                self.transport.sendto(data_packet, (peer.endpoint_ip, peer.endpoint_port))
                peer.bytes_sent += len(data_packet)
        except Exception as e:
            logger.error("Failed to send data to peer %s: %s", peer.name, e)


async def tun_reader_loop(
    tun: TunInterface,
    protocol: NovaTunnelServerProtocol,
    registry: PeerRegistry,
    stop_event: asyncio.Event,
) -> None:
    """Continuously reads IP packets from the TUN interface and routes them to peers."""
    loop = asyncio.get_running_loop()
    logger.info("TUN reader loop started on interface %s", tun.name)

    while not stop_event.is_set():
        try:
            # Asynchronous non-blocking read using thread pool to support POSIX TUN fds
            raw_packet = await loop.run_in_executor(None, tun.read, 2048)
            if not raw_packet or len(raw_packet) < 20:
                continue

            # Parse IPv4 header
            version = (raw_packet[0] >> 4) & 0x0F
            if version != 4:
                # IPv6 or non-IPv4 packet; skip
                continue

            # Extract destination IPv4 address (bytes 16 to 20)
            dest_ip_bytes = raw_packet[16:20]
            dest_ip = socket.inet_ntoa(dest_ip_bytes)

            # Match peer by assigned VPN IP
            peer = registry.get_by_ip(dest_ip)
            if peer and peer.is_connected:
                protocol.send_data_to_peer(peer, raw_packet)
        except asyncio.CancelledError:
            break
        except Exception as e:
            if not stop_event.is_set():
                logger.error("Error in TUN reader loop: %s", e)
                await asyncio.sleep(0.01)


async def peer_monitor_loop(
    registry: PeerRegistry,
    stop_event: asyncio.Event,
    timeout_seconds: float = 60.0,
) -> None:
    """Periodically check peer activity and mark unresponsive peers disconnected."""
    logger.info("Peer monitor loop started (timeout=%ss)", timeout_seconds)
    while not stop_event.is_set():
        try:
            await asyncio.sleep(10)
            now = time.time()
            for peer in registry.list_peers():
                if peer.is_connected:
                    if peer.last_seen > 0 and (now - peer.last_seen) > timeout_seconds:
                        logger.info("Peer '%s' (%s) timed out (inactivity)", peer.name, peer.assigned_ip)
                        peer.is_connected = False
                        peer.session_id = 0
                        peer.session_key_hex = ""
            # Persist registry metrics
            registry.save_to_file()
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.warning("Error in peer monitor loop: %s", e)


def start_dashboard_thread(app, host: str, port: int) -> threading.Thread:
    """Start the Flask dashboard in a background daemon thread."""
    def run_flask():
        import werkzeug.serving
        logger.info("Starting NovaTunnel Web Dashboard on http://%s:%d", host, port)
        # Run Flask server quietly
        logging.getLogger("werkzeug").setLevel(logging.ERROR)
        app.run(host=host, port=port, debug=False, use_reloader=False)

    thread = threading.Thread(target=run_flask, daemon=True, name="NovaTunnelDashboard")
    thread.start()
    return thread


async def run_server(config_dict: Optional[dict] = None) -> None:
    """Main asynchronous entry point to configure, start, and run the NovaTunnel VPN server."""
    config = config_dict or load_server_config()
    server_cfg = config["server"]
    dash_cfg = config.get("dashboard", {})

    setup_logging()
    logger.info("Initializing NovaTunnel VPN Server...")

    # Load peer registry
    peers_path = server_cfg.get("peers_file", "/etc/novatunnel/peers.json")
    registry = PeerRegistry(storage_path=peers_path)

    # Initialize TUN interface
    tun_name = server_cfg.get("tun_name", "nova0")
    server_vpn_ip = server_cfg.get("server_vpn_ip", "10.8.0.1")
    vpn_subnet = server_cfg.get("vpn_subnet", "10.8.0.0/24")
    mtu = int(server_cfg.get("mtu", 1420))
    dns_servers = server_cfg.get("dns", ["1.1.1.1", "8.8.8.8"])

    tun = TunInterface(name=tun_name)
    try:
        tun.open()
        tun.configure(local_ip=server_vpn_ip, mtu=mtu)
        tun.up()
    except NotImplementedError as e:
        logger.warning("TUN device initialization warning: %s", e)
    except Exception as e:
        logger.error("Failed to setup TUN device: %s", e)
        raise

    # Setup NAT & Forwarding on host
    outbound_interface = get_default_interface()
    setup_nat(outbound_interface=outbound_interface, vpn_subnet=vpn_subnet, tun_name=tun_name)

    # Launch dashboard if enabled
    if dash_cfg.get("enabled", False):
        try:
            from dashboard.app import create_app
            flask_app = create_app(registry=registry, server_config=server_cfg)
            start_dashboard_thread(
                app=flask_app,
                host=dash_cfg.get("host", "0.0.0.0"),
                port=int(dash_cfg.get("port", 8080)),
            )
        except Exception as e:
            logger.error("Failed to start Web Dashboard: %s", e)

    # Create UDP Server endpoint
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    host = server_cfg.get("host", "0.0.0.0")
    port = int(server_cfg.get("port", 51820))

    listen = loop.create_datagram_endpoint(
        lambda: NovaTunnelServerProtocol(
            registry=registry,
            tun=tun,
            server_vpn_ip=server_vpn_ip,
            vpn_subnet=vpn_subnet,
            dns_servers=dns_servers,
            mtu=mtu,
        ),
        local_addr=(host, port),
    )
    transport, protocol = await listen

    # Background workers
    tasks = []
    if tun.is_open:
        tasks.append(asyncio.create_task(tun_reader_loop(tun, protocol, registry, stop_event)))
    tasks.append(asyncio.create_task(peer_monitor_loop(registry, stop_event)))

    # Handle system termination signals
    def shutdown_signal():
        logger.info("Shutdown signal received. Stopping NovaTunnel Server...")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, shutdown_signal)
        except NotImplementedError:
            # Signal handlers not implemented on Windows event loop
            pass

    try:
        logger.info("NovaTunnel VPN Server running. Press Ctrl+C to terminate.")
        await stop_event.wait()
    finally:
        logger.info("Cleaning up server resources...")
        stop_event.set()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

        if transport:
            transport.close()

        teardown_nat(outbound_interface=outbound_interface, vpn_subnet=vpn_subnet, tun_name=tun_name)
        tun.close()
        registry.save_to_file()
        logger.info("NovaTunnel VPN Server stopped cleanly.")
