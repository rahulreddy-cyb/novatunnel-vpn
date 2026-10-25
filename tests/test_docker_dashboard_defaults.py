from pathlib import Path
import os
import re
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]

compose = (ROOT / "docker-compose.yml").read_text()
env_example = (ROOT / ".env.example").read_text()

print("=== DOCKER DASHBOARD SECURITY TEST ===")

def check_compose(key, value):
    pattern = (
        rf"(?m)^\s*-\s*"
        rf"{re.escape(key)}={re.escape(value)}\s*$"
    )
    assert re.search(pattern, compose), key

check_compose("NOVATUNNEL_DASHBOARD_ENABLED", "false")
check_compose("NOVATUNNEL_DASHBOARD_HOST", "127.0.0.1")

print("PASS 1: Docker dashboard disabled and localhost-only")

assert "8080:8080" not in compose
assert "51820:51820/udp" in compose

print("PASS 2: Dashboard port not published; VPN port retained")

check_compose(
    "NOVATUNNEL_DASHBOARD_SECRET",
    "${NOVATUNNEL_DASHBOARD_SECRET:-}",
)
check_compose(
    "NOVATUNNEL_DASHBOARD_PASS",
    "${NOVATUNNEL_DASHBOARD_PASS:-}",
)

print("PASS 3: Disabled dashboard credentials optional")

assert re.search(
    r"(?m)^NOVATUNNEL_DASHBOARD_ENABLED=false$", env_example
)
assert re.search(
    r"(?m)^NOVATUNNEL_DASHBOARD_HOST=127\.0\.0\.1$",
    env_example,
)

print("PASS 4: Example environment defaults secure")

with patch.dict(os.environ, {}, clear=True):
    try:
        from dashboard.app import create_app
        create_app()
    except RuntimeError as exc:
        assert "NOVATUNNEL_DASHBOARD_SECRET" in str(exc)
    else:
        raise AssertionError(
            "Dashboard accepted missing credentials"
        )

print("PASS 5: Dashboard rejects missing credentials")
print("=== DOCKER DASHBOARD SECURITY TESTS COMPLETE ===")
