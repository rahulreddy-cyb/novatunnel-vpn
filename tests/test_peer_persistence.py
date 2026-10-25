#!/usr/bin/env python3
"""Isolated peer-registry persistence security tests."""

import json
import stat
import tempfile
from pathlib import Path

from novatunnel.peer import PeerRegistry


with tempfile.TemporaryDirectory() as folder:
    path = Path(folder) / "peers.json"
    registry = PeerRegistry(str(path))

    key = "ab" * 32

    peer = registry.add_peer(
        name="security-test-peer",
        public_key_hex="11" * 32,
        assigned_ip="10.8.0.2",
    )

    peer.session_id = 4242
    peer.session_key_hex = key
    peer.is_connected = True
    peer.endpoint_ip = "127.0.0.1"
    peer.endpoint_port = 51820

    # Save registry while an active session exists.
    registry.add_peer(
        name="second-peer",
        public_key_hex="22" * 32,
        assigned_ip="10.8.0.3",
    )

    stored = path.read_text()
    records = json.loads(stored)

    for field in (
        "session_key_hex",
        "session_id",
        "is_connected",
        "endpoint_ip",
        "endpoint_port",
    ):
        assert field not in records[0]

    assert key not in stored
    print("PASS: Session secrets excluded from JSON")

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    print("PASS: Registry permissions are 0600")

    assert peer.session_key_hex == key
    assert peer.is_connected
    print("PASS: Active session retained in memory")

    restarted = PeerRegistry(str(path))
    loaded = restarted.get_by_public_key("11" * 32)

    assert loaded is not None
    assert loaded.assigned_ip == "10.8.0.2"
    assert loaded.session_id == 0
    assert loaded.session_key_hex == ""
    assert not loaded.is_connected
    print("PASS: Registration survives safe restart")

    # Simulate an older database containing session credentials.
    records[0]["session_key_hex"] = key
    records[0]["session_id"] = 4242
    records[0]["is_connected"] = True
    path.write_text(json.dumps(records))

    legacy = PeerRegistry(str(path))
    recovered = legacy.get_by_public_key("11" * 32)

    assert recovered.session_key_hex == ""
    assert recovered.session_id == 0
    assert not recovered.is_connected
    print("PASS: Legacy session credentials cleared")

    legacy.save_to_file()
    clean = path.read_text()

    assert key not in clean
    assert "session_key_hex" not in clean
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    print("PASS: Legacy JSON sanitized on save")


# Verify dashboard-facing peer serialization.
from novatunnel.peer import Peer

dashboard_peer = Peer(
    peer_id="dashboard-test",
    name="test-peer",
    public_key_hex="11" * 32,
    assigned_ip="10.8.0.2",
    session_id=4242,
    session_key_hex="ab" * 32,
    is_connected=True,
)

serialized = dashboard_peer.to_dict()

assert "session_key_hex" not in serialized
assert "ab" * 32 not in json.dumps(serialized)
print("PASS: Dashboard serialization excludes session key")

assert serialized["name"] == "test-peer"
assert serialized["assigned_ip"] == "10.8.0.2"
assert serialized["is_connected"] is True
print("PASS: Dashboard peer metadata preserved")

assert dashboard_peer.session_key_hex == "ab" * 32
print("PASS: Live session key preserved in memory")

print("=== PHASE 6 PERSISTENCE TESTS COMPLETE ===")
