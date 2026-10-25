"""
NovaTunnel VPN - Peer Data Model & Registry
Manages peer identity, crypto credentials, dynamic sessions, IP allocation, and metrics.
"""

import ipaddress
import json
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

logger = logging.getLogger("novatunnel.peer")


@dataclass
class Peer:
    """Represents a NovaTunnel VPN client peer."""
    peer_id: str
    name: str
    public_key_hex: str
    assigned_ip: str
    session_id: int = 0
    session_key_hex: str = ""
    endpoint_ip: str = ""
    endpoint_port: int = 0
    last_seen: float = 0.0
    bytes_sent: int = 0
    bytes_recv: int = 0
    is_connected: bool = False
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        """Serialize peer to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Peer":
        """Deserialize peer from dictionary."""
        return cls(
            peer_id=str(data.get("peer_id", str(uuid.uuid4()))),
            name=str(data.get("name", "peer")),
            public_key_hex=str(data.get("public_key_hex", "")),
            assigned_ip=str(data.get("assigned_ip", "")),
            session_id=int(data.get("session_id", 0)),
            session_key_hex=str(data.get("session_key_hex", "")),
            endpoint_ip=str(data.get("endpoint_ip", "")),
            endpoint_port=int(data.get("endpoint_port", 0)),
            last_seen=float(data.get("last_seen", 0.0)),
            bytes_sent=int(data.get("bytes_sent", 0)),
            bytes_recv=int(data.get("bytes_recv", 0)),
            is_connected=bool(data.get("is_connected", False)),
            created_at=float(data.get("created_at", time.time())),
        )


class PeerRegistry:
    """Thread-safe registry for managing registered and active VPN peers."""

    def __init__(self, storage_path: Optional[str] = None):
        self.storage_path = storage_path
        self._peers: Dict[str, Peer] = {}  # peer_id -> Peer
        self._lock = threading.RLock()
        if self.storage_path and os.path.exists(self.storage_path):
            self.load_from_file(self.storage_path)

    def add_peer(
        self,
        name: str,
        public_key_hex: str,
        assigned_ip: Optional[str] = None,
        peer_id: Optional[str] = None,
        subnet: str = "10.8.0.0/24",
    ) -> Peer:
        """Register a new peer or update an existing one by public key."""
        with self._lock:
            # Normalize public key
            norm_pubkey = public_key_hex.strip().lower()

            # Check if peer with same public key already exists
            existing = self.get_by_public_key(norm_pubkey)
            if existing:
                existing.name = name
                if assigned_ip:
                    existing.assigned_ip = assigned_ip
                if self.storage_path:
                    self.save_to_file(self.storage_path)
                return existing

            # Allocate IP if not provided
            if not assigned_ip:
                assigned_ip = self.allocate_ip(subnet=subnet)

            pid = peer_id or str(uuid.uuid4())
            peer = Peer(
                peer_id=pid,
                name=name,
                public_key_hex=norm_pubkey,
                assigned_ip=assigned_ip,
                created_at=time.time(),
            )
            self._peers[pid] = peer
            if self.storage_path:
                self.save_to_file(self.storage_path)
            logger.info("Added peer %s (%s) with IP %s", name, pid, assigned_ip)
            return peer

    def remove_peer(self, peer_id: str) -> bool:
        """Remove a peer by its ID."""
        with self._lock:
            if peer_id in self._peers:
                removed = self._peers.pop(peer_id)
                if self.storage_path:
                    self.save_to_file(self.storage_path)
                logger.info("Removed peer %s (%s)", removed.name, peer_id)
                return True
            return False

    def get_by_id(self, peer_id: str) -> Optional[Peer]:
        """Lookup peer by unique UUID."""
        with self._lock:
            return self._peers.get(peer_id)

    def get_by_public_key(self, public_key_hex: str) -> Optional[Peer]:
        """Lookup peer by 32-byte X25519 public key hex string."""
        with self._lock:
            norm = public_key_hex.strip().lower()
            for peer in self._peers.values():
                if peer.public_key_hex.strip().lower() == norm:
                    return peer
            return None

    def get_by_session_id(self, session_id: int) -> Optional[Peer]:
        """Lookup active peer by active uint32 session ID."""
        with self._lock:
            if session_id == 0:
                return None
            for peer in self._peers.values():
                if peer.session_id == session_id:
                    return peer
            return None

    def get_by_ip(self, ip: str) -> Optional[Peer]:
        """Lookup peer by assigned VPN IP address."""
        with self._lock:
            clean_ip = ip.strip()
            for peer in self._peers.values():
                if peer.assigned_ip == clean_ip:
                    return peer
            return None

    def get_by_endpoint(self, ip: str, port: int) -> Optional[Peer]:
        """Lookup peer by remote UDP socket endpoint."""
        with self._lock:
            for peer in self._peers.values():
                if peer.endpoint_ip == ip and peer.endpoint_port == port:
                    return peer
            return None

    def list_peers(self) -> List[Peer]:
        """Return a snapshot list of all registered peers."""
        with self._lock:
            return list(self._peers.values())

    def update_peer(self, peer: Peer) -> None:
        """Update or insert peer state."""
        with self._lock:
            self._peers[peer.peer_id] = peer

    def update_traffic(self, peer_id: str, sent_delta: int = 0, recv_delta: int = 0) -> None:
        """Increment traffic counters for a peer."""
        with self._lock:
            peer = self._peers.get(peer_id)
            if peer:
                peer.bytes_sent += sent_delta
                peer.bytes_recv += recv_delta
                peer.last_seen = time.time()

    def allocate_ip(self, subnet: str = "10.8.0.0/24") -> str:
        """
        Allocate the next free IPv4 address in the given subnet.
        Skips network address (.0), server gateway (.1), and broadcast (.255).
        """
        with self._lock:
            net = ipaddress.ip_network(subnet, strict=False)
            assigned = {p.assigned_ip for p in self._peers.values() if p.assigned_ip}
            
            # Skip first address (server gateway, e.g. 10.8.0.1)
            hosts = list(net.hosts())
            if len(hosts) <= 1:
                raise ValueError(f"Subnet {subnet} has insufficient hosts")

            # hosts[0] is server IP (10.8.0.1), clients start from hosts[1] (10.8.0.2)
            for host in hosts[1:]:
                ip_str = str(host)
                if ip_str not in assigned:
                    return ip_str

            raise RuntimeError(f"IP pool exhausted for subnet {subnet}")

    def save_to_file(self, path: Optional[str] = None) -> None:
        """Persist peer registry to a JSON file."""
        target_path = path or self.storage_path
        if not target_path:
            return

        with self._lock:
            os.makedirs(os.path.dirname(os.path.abspath(target_path)), exist_ok=True)
            data = [peer.to_dict() for peer in self._peers.values()]
            temp_path = f"{target_path}.tmp"
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(temp_path, target_path)

    def load_from_file(self, path: Optional[str] = None) -> None:
        """Load peer registry from a JSON file."""
        target_path = path or self.storage_path
        if not target_path or not os.path.exists(target_path):
            return

        with self._lock:
            try:
                if os.path.getsize(target_path) == 0:
                    return
                with open(target_path, "r", encoding="utf-8") as f:
                    raw_list = json.load(f)
                self._peers.clear()
                for item in raw_list:
                    peer = Peer.from_dict(item)
                    # Reset connection state upon server restart
                    peer.is_connected = False
                    peer.session_id = 0
                    peer.session_key_hex = ""
                    self._peers[peer.peer_id] = peer
                logger.info("Loaded %d peers from %s", len(self._peers), target_path)
            except Exception as e:
                logger.error("Failed to load peer registry from %s: %s", target_path, e)
