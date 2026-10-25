import os
from unittest.mock import patch

from novatunnel.config import load_server_config

print("=== PYTHON DASHBOARD DEFAULT SECURITY TEST ===")

with patch.dict(os.environ, {}, clear=True):
    config = load_server_config()
    dashboard = config["dashboard"]

    assert dashboard["enabled"] is False
    assert dashboard["host"] == "127.0.0.1"
    assert dashboard["secret_key"] == ""
    assert dashboard["password"] == ""

print("PASS 1: Dashboard disabled by default")
print("PASS 2: Dashboard restricted to localhost")
print("PASS 3: No default dashboard credentials")

# Explicit environment overrides must still work.
with patch.dict(
    os.environ,
    {
        "NOVATUNNEL_DASHBOARD_ENABLED": "true",
        "NOVATUNNEL_DASHBOARD_HOST": "127.0.0.1",
    },
    clear=True,
):
    config = load_server_config()

    assert config["dashboard"]["enabled"] is True
    assert config["dashboard"]["host"] == "127.0.0.1"

print("PASS 4: Explicit dashboard configuration supported")
print("=== RUNTIME DASHBOARD TESTS COMPLETE ===")
