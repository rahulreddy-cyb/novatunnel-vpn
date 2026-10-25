#!/usr/bin/env python3
"""Isolated NovaTunnel dashboard login throttling tests."""

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

password = "TemporaryTestPassword-12345!"
base = "https://localhost"

config = {
    "dashboard": {
        "secret_key": secrets.token_hex(32),
        "username": "test-admin",
        "password": password,
    },
    "server": {},
}

with patch.object(module, "load_server_config", return_value=config):
    app = module.create_app(registry=PeerRegistry())

app.testing = True
client = app.test_client()


def get_token(client_obj, remote_ip=None):
    kwargs = {"base_url": base}
    if remote_ip:
        kwargs["environ_overrides"] = {
            "REMOTE_ADDR": remote_ip
        }

    page = client_obj.get("/login", **kwargs)
    assert page.status_code == 200

    match = re.search(
        r'name="csrf_token"\s+value="([^"]+)"',
        page.get_data(as_text=True),
    )
    assert match
    return match.group(1)


token = get_token(client)


def login(attempt, headers=None):
    return client.post(
        "/login",
        base_url=base,
        data={
            "username": "test-admin",
            "password": attempt,
            "csrf_token": token,
        },
        headers={
            "Referer": base + "/login",
            **(headers or {}),
        },
    )


for _ in range(5):
    response = login("wrong-password")
    assert response.status_code == 200

print("PASS: Five failed login attempts recorded")

response = login(password)
assert response.status_code == 429
assert int(response.headers["Retry-After"]) > 0
print("PASS: Further login attempts blocked")

response = login(
    password,
    {"X-Forwarded-For": "203.0.113.99"},
)
assert response.status_code == 429
print("PASS: Forwarded-header spoofing cannot bypass block")

other = app.test_client()
other_ip = "192.0.2.25"
other_token = get_token(other, other_ip)

response = other.post(
    "/login",
    base_url=base,
    environ_overrides={"REMOTE_ADDR": other_ip},
    headers={"Referer": base + "/login"},
    data={
        "username": "test-admin",
        "password": password,
        "csrf_token": other_token,
    },
)

assert response.status_code == 302
print("PASS: Legitimate login from another IP accepted")

response = other.get(
    "/api/status",
    base_url=base,
    environ_overrides={"REMOTE_ADDR": other_ip},
)
assert response.status_code == 200
print("PASS: Authenticated dashboard remains accessible")

print("=== LOGIN RATE-LIMIT SECURITY TESTS COMPLETE ===")
