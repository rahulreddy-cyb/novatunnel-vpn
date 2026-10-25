#!/usr/bin/env python3
"""Isolated dashboard CSRF security regression tests."""

import os
import re
import secrets
from importlib import import_module
from unittest.mock import patch

from novatunnel.peer import PeerRegistry

os.environ["NOVATUNNEL_DASHBOARD_SECRET"] = secrets.token_hex(32)
os.environ["NOVATUNNEL_DASHBOARD_USER"] = "test-admin"
os.environ["NOVATUNNEL_DASHBOARD_PASS"] = "TemporaryTestPassword-12345!"

module = import_module("dashboard.app")
registry = PeerRegistry()
password = "TemporaryTestPassword-12345!"

config = {
    "dashboard": {
        "secret_key": secrets.token_hex(32),
        "username": "test-admin",
        "password": password,
    },
    "server": {
        "vpn_subnet": "10.8.0.0/24",
        "host": "127.0.0.1",
        "port": 51820,
    },
}

with patch.object(module, "load_server_config", return_value=config):
    app = module.create_app(registry=registry)

app.testing = True
client = app.test_client()

BASE_URL = "https://localhost"

def https_get(*args, **kwargs):
    kwargs.setdefault("base_url", BASE_URL)
    return client.get(*args, **kwargs)

def https_post(*args, **kwargs):
    kwargs.setdefault("base_url", BASE_URL)

    headers = dict(kwargs.pop("headers", {}) or {})
    headers.setdefault("Referer", BASE_URL + "/")
    kwargs["headers"] = headers

    return client.post(*args, **kwargs)



def get_csrf(response):
    html = response.get_data(as_text=True)
    for pattern in (
        r'name="csrf_token"\s+value="([^"]+)"',
        r'"X-CSRFToken"\s*:\s*"([^"]+)"',
    ):
        match = re.search(pattern, html)
        if match:
            return match.group(1)
    raise AssertionError("CSRF token not found")


page = https_get("/login")
assert page.status_code == 200
login_token = get_csrf(page)
print("PASS 1: Login CSRF token generated")

response = https_post(
    "/login",
    data={"username": "test-admin", "password": password},
)
assert response.status_code == 400
print("PASS 2: Missing login CSRF rejected")

response = https_post(
    "/login",
    data={
        "username": "test-admin",
        "password": password,
        "csrf_token": "invalid",
    },
)
assert response.status_code == 400
print("PASS 3: Invalid login CSRF rejected")

response = https_post(
    "/login",
    data={
        "username": "test-admin",
        "password": password,
        "csrf_token": login_token,
    },
)
assert response.status_code == 302
print("PASS 4: Valid login accepted")

page = https_get("/peers")
assert page.status_code == 200
token = get_csrf(page)

response = https_post(
    "/peers/add",
    json={"name": "csrf-test-peer"},
)
assert response.status_code == 400
assert len(registry.list_peers()) == 0
print("PASS 5: Peer creation without CSRF rejected")

response = https_post(
    "/peers/add",
    json={"name": "csrf-test-peer"},
    headers={"X-CSRFToken": token},
)
assert response.status_code == 200
assert len(registry.list_peers()) == 1
peer_id = registry.list_peers()[0].peer_id
print("PASS 6: Valid peer creation accepted")

response = https_post(f"/peers/{peer_id}/delete")
assert response.status_code == 400
assert registry.get_by_id(peer_id) is not None
print("PASS 7: Peer deletion without CSRF rejected")

response = https_post(
    f"/peers/{peer_id}/delete",
    data={"csrf_token": token},
)
assert response.status_code == 302
assert registry.get_by_id(peer_id) is None
print("PASS 8: Valid peer deletion accepted")

print("=== PHASE 7B ALL CSRF TESTS COMPLETE ===")
