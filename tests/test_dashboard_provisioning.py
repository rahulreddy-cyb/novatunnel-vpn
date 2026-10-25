#!/usr/bin/env python3
"""Isolated NovaTunnel private-key provisioning security tests."""

import os
import re
import secrets
from importlib import import_module
from unittest.mock import patch

from novatunnel.peer import PeerRegistry

# Test-only values, not deployment credentials.
os.environ["NOVATUNNEL_DASHBOARD_SECRET"] = secrets.token_hex(32)
os.environ["NOVATUNNEL_DASHBOARD_USER"] = "test-admin"
os.environ["NOVATUNNEL_DASHBOARD_PASS"] = "TemporaryTestPassword-12345!"

module = import_module("dashboard.app")
registry = PeerRegistry()
password = "TemporaryTestPassword-12345!"
base = "https://localhost"

config = {
    "dashboard": {
        "secret_key": secrets.token_hex(32),
        "username": "test-admin",
        "password": password,
    },
    "server": {
        "host": "127.0.0.1",
        "port": 51820,
        "vpn_subnet": "10.8.0.0/24",
    },
}

with patch.object(module, "load_server_config", return_value=config):
    app = module.create_app(registry=registry)

app.testing = True
client = app.test_client()

# 1. Unauthenticated configuration access is denied.
response = client.get(
    "/peers/example/config", base_url=base
)
assert response.status_code == 302
print("PASS 1: Unauthenticated configuration access blocked")

# Authenticate with a valid CSRF token.
page = client.get("/login", base_url=base)

match = re.search(
    r'name="csrf_token"\s+value="([^"]+)"',
    page.get_data(as_text=True),
)
assert match

response = client.post(
    "/login",
    base_url=base,
    headers={"Referer": base + "/login"},
    data={
        "username": "test-admin",
        "password": password,
        "csrf_token": match.group(1),
    },
)
assert response.status_code == 302

# Obtain the token rendered for the JavaScript API.
page = client.get("/peers", base_url=base)
match = re.search(
    r'"X-CSRFToken"\s*:\s*"([^"]+)"',
    page.get_data(as_text=True),
)
assert match
token = match.group(1)

# 2. Provisioning requires valid CSRF.
response = client.post(
    "/peers/add",
    base_url=base,
    headers={"Referer": base + "/peers"},
    json={"name": "provisioning-test"},
)
assert response.status_code == 400
assert not registry.list_peers()
print("PASS 2: Provisioning without CSRF rejected")

# 3. Legitimate provisioning succeeds.
response = client.post(
    "/peers/add",
    base_url=base,
    headers={
        "Referer": base + "/peers",
        "X-CSRFToken": token,
    },
    json={"name": "provisioning-test"},
)

assert response.status_code == 200, (
    response.status_code,
    response.get_data(as_text=True)[:250],
)

result = response.get_json()
assert result["success"] is True

peer_id = result["peer"]["peer_id"]
client_config = result["config_toml"]

match = re.search(
    r'(?m)^private_key = "([0-9a-fA-F]{64})"$',
    client_config,
)
assert match, "Valid private key missing from initial configuration"

private_key = match.group(1)

assert registry.get_by_id(peer_id) is not None
assert registry.get_by_id(peer_id).public_key_hex == (
    result["client_public_key"]
)

print("PASS 3: Initial configuration contains valid key")

# 4. Avoid redundant private-key fields and JSON session secrets.
assert "client_private_key" not in result
assert "session_key_hex" not in result["peer"]
print("PASS 4: Redundant secret fields excluded")

# 5. Sensitive responses must not be cached.
assert "no-store" in response.headers.get("Cache-Control", "")
assert response.headers.get("Pragma") == "no-cache"
assert response.headers.get("X-Content-Type-Options") == "nosniff"
print("PASS 5: Provisioning response is non-cacheable")

# 6. Old configuration downloads are disabled.
response = client.get(
    f"/peers/{peer_id}/config", base_url=base
)
assert response.status_code == 410
assert private_key not in response.get_data(as_text=True)
assert "no-store" in response.headers.get("Cache-Control", "")
print("PASS 6: Repeated config download disabled")

# 7. Old secret-bearing QR downloads are disabled.
response = client.get(
    f"/peers/{peer_id}/qrcode", base_url=base
)
assert response.status_code == 410
assert "no-store" in response.headers.get("Cache-Control", "")
print("PASS 7: Repeated QR retrieval disabled")

# 8. Unknown peers must not return configurations.
response = client.get(
    "/peers/nonexistent-peer/config", base_url=base
)
assert response.status_code == 404
print("PASS 8: Unknown peer configuration unavailable")

# 9. Configuration generation cannot silently omit a key.
try:
    module.generate_client_toml(
        registry.get_by_id(peer_id),
        "",
        config["server"],
    )
except ValueError:
    print("PASS 9: Missing private key explicitly rejected")
else:
    raise AssertionError("Missing private key was accepted")

print("=== PHASE 7E PROVISIONING SECURITY TESTS COMPLETE ===")
