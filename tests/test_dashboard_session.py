#!/usr/bin/env python3
"""Dashboard authentication and secure-session regression tests."""

import os
import re
import secrets
from datetime import timedelta
from importlib import import_module
from unittest.mock import patch
from urllib.parse import urlencode

from novatunnel.peer import PeerRegistry

os.environ["NOVATUNNEL_DASHBOARD_SECRET"] = secrets.token_hex(32)
os.environ["NOVATUNNEL_DASHBOARD_USER"] = "test-admin"
os.environ["NOVATUNNEL_DASHBOARD_PASS"] = "TemporaryTestPassword-12345!"

module = import_module("dashboard.app")

password = "TemporaryTestPassword-12345!"
base = "https://localhost"

def config(password_value=password, secret=None):
    return {
        "dashboard": {
            "secret_key": secret if secret is not None else "s" * 64,
            "username": "test-admin",
            "password": password_value,
        },
        "server": {},
    }

with patch.object(
    module, "load_server_config",
    return_value=config(),
):
    app = module.create_app(registry=PeerRegistry())

app.testing = True

def login(client, next_target=None):
    url = "/login"
    if next_target is not None:
        url += "?" + urlencode({"next": next_target})

    page = client.get(url, base_url=base)
    assert page.status_code == 200

    match = re.search(
        r'name="csrf_token"\s+value="([^"]+)"',
        page.get_data(as_text=True),
    )
    assert match

    return client.post(
        url,
        base_url=base,
        headers={"Referer": base + "/login"},
        data={
            "username": "test-admin",
            "password": password,
            "csrf_token": match.group(1),
        },
    )

client = app.test_client()

response = client.get("/api/status", base_url=base)
assert response.status_code == 302
print("PASS 1: Unauthenticated API access blocked")

response = login(client, "https://evil.example/")
assert response.status_code == 302
assert response.location == "/"
print("PASS 2: External redirect blocked")

cookie = response.headers.get("Set-Cookie", "")

assert "Secure" in cookie
assert "HttpOnly" in cookie
assert "SameSite=Lax" in cookie
print("PASS 3: Secure cookie attributes enabled")

assert app.permanent_session_lifetime == timedelta(minutes=30)
assert app.config["SESSION_REFRESH_EACH_REQUEST"] is False
assert "Expires=" in cookie
print("PASS 4: Session expiration configured")

response = client.get("/api/status", base_url=base)
assert response.status_code == 200
print("PASS 5: Authenticated HTTPS access works")

second = app.test_client()
response = login(second, "/peers")
assert response.status_code == 302
assert response.location == "/peers"
print("PASS 6: Safe internal redirect accepted")

third = app.test_client()
response = login(third, "//evil.example/")
assert response.status_code == 302
assert response.location == "/"
print("PASS 7: Protocol-relative redirect blocked")

for bad_password, bad_secret in [
    ("admin", "s" * 64),
    (password, "change-me-in-production-novatunnel"),
]:
    with patch.object(
        module, "load_server_config",
        return_value=config(bad_password, bad_secret),
    ):
        try:
            module.create_app(registry=PeerRegistry())
        except RuntimeError:
            pass
        else:
            raise AssertionError("Unsafe configuration accepted")

print("PASS 8: Insecure defaults rejected")
print("=== DASHBOARD SESSION SECURITY TESTS COMPLETE ===")
