"""
NovaTunnel VPN - Configuration Management
Handles loading, environment variable overrides, validation, and serialization of TOML configurations.
"""

import copy
import logging
import os
from typing import Any, Dict, Optional

try:
    import tomllib  # Built-in in Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # Fallback for Python 3.10
    except ImportError:
        tomllib = None

try:
    import tomli_w
except ImportError:
    tomli_w = None

logger = logging.getLogger("novatunnel.config")

DEFAULT_SERVER_CONFIG: Dict[str, Any] = {
    "server": {
        "host": "0.0.0.0",
        "port": 51820,
        "private_key": "",
        "public_key": "",
        "vpn_subnet": "10.8.0.0/24",
        "server_vpn_ip": "10.8.0.1",
        "tun_name": "nova0",
        "mtu": 1420,
        "dns": ["1.1.1.1", "8.8.8.8"],
        "max_peers": 50,
        "peers_file": "/etc/novatunnel/peers.json",
    },
    "dashboard": {
        "enabled": False,
        "host": "127.0.0.1",
        "port": 8080,
        "secret_key": "",
        "username": "admin",
        "password": "",
    },
}

DEFAULT_CLIENT_CONFIG: Dict[str, Any] = {
    "client": {
        "server_host": "127.0.0.1",
        "server_port": 51820,
        "server_public_key": "",
        "private_key": "",
        "public_key": "",
        "assigned_ip": "",
        "tun_name": "nova-client",
        "mtu": 1420,
        "keepalive_interval": 25,
        "route_all_traffic": True,
        "dns": ["1.1.1.1", "8.8.8.8"],
    }
}


def _deep_merge(base: dict, update: dict) -> dict:
    """Recursively merge dictionary `update` into `base`."""
    result = copy.deepcopy(base)
    for k, v in update.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = copy.deepcopy(v)
    return result


def _simple_dump_toml(data: dict) -> str:
    """Fallback TOML serializer if tomli_w is not installed."""
    lines = []
    top_level = {}
    sections = {}

    for k, v in data.items():
        if isinstance(v, dict):
            sections[k] = v
        else:
            top_level[k] = v

    def format_val(val: Any) -> str:
        if isinstance(val, bool):
            return "true" if val else "false"
        elif isinstance(val, (int, float)):
            return str(val)
        elif isinstance(val, str):
            return f'"{val}"'
        elif isinstance(val, list):
            items = ", ".join(format_val(x) for x in val)
            return f"[{items}]"
        return f'"{str(val)}"'

    for k, v in top_level.items():
        lines.append(f"{k} = {format_val(v)}")
    if top_level and sections:
        lines.append("")

    for sec_name, sec_dict in sections.items():
        lines.append(f"[{sec_name}]")
        for k, v in sec_dict.items():
            lines.append(f"{k} = {format_val(v)}")
        lines.append("")

    return "\n".join(lines).strip() + "\n"


def load_server_config(path: Optional[str] = None) -> dict:
    """
    Load server TOML configuration, apply environment variable overrides,
    and fallback to default values.
    """
    config = copy.deepcopy(DEFAULT_SERVER_CONFIG)

    if path and os.path.exists(path):
        if tomllib is None:
            raise RuntimeError("TOML parser not available. Install tomli or use Python 3.11+.")
        with open(path, "rb") as f:
            loaded = tomllib.load(f)
            config = _deep_merge(config, loaded)
        logger.info("Loaded server configuration from %s", path)
    elif path:
        logger.warning("Server config path %s not found, using default configuration", path)

    # Environment variable overrides
    s = config["server"]
    if os.getenv("NOVATUNNEL_HOST"):
        s["host"] = os.getenv("NOVATUNNEL_HOST")
    if os.getenv("NOVATUNNEL_PORT"):
        s["port"] = int(os.getenv("NOVATUNNEL_PORT", "51820"))
    if os.getenv("NOVATUNNEL_PRIVATE_KEY"):
        s["private_key"] = os.getenv("NOVATUNNEL_PRIVATE_KEY")
    if os.getenv("NOVATUNNEL_SUBNET"):
        s["vpn_subnet"] = os.getenv("NOVATUNNEL_SUBNET")
    if os.getenv("NOVATUNNEL_SERVER_VPN_IP"):
        s["server_vpn_ip"] = os.getenv("NOVATUNNEL_SERVER_VPN_IP")
    if os.getenv("NOVATUNNEL_PEERS_FILE"):
        s["peers_file"] = os.getenv("NOVATUNNEL_PEERS_FILE")

    d = config["dashboard"]
    if os.getenv("NOVATUNNEL_DASHBOARD_ENABLED"):
        d["enabled"] = os.getenv("NOVATUNNEL_DASHBOARD_ENABLED", "true").lower() in ("true", "1", "yes")
    if os.getenv("NOVATUNNEL_DASHBOARD_HOST"):
        d["host"] = os.getenv("NOVATUNNEL_DASHBOARD_HOST")
    if os.getenv("NOVATUNNEL_DASHBOARD_PORT"):
        d["port"] = int(os.getenv("NOVATUNNEL_DASHBOARD_PORT", "8080"))
    if os.getenv("NOVATUNNEL_DASHBOARD_SECRET"):
        d["secret_key"] = os.getenv("NOVATUNNEL_DASHBOARD_SECRET")
    if os.getenv("NOVATUNNEL_DASHBOARD_USER"):
        d["username"] = os.getenv("NOVATUNNEL_DASHBOARD_USER")
    if os.getenv("NOVATUNNEL_DASHBOARD_PASS"):
        d["password"] = os.getenv("NOVATUNNEL_DASHBOARD_PASS")

    return config


def load_client_config(path: Optional[str] = None) -> dict:
    """
    Load client TOML configuration, apply environment variable overrides,
    and fallback to default values.
    """
    config = copy.deepcopy(DEFAULT_CLIENT_CONFIG)

    if path and os.path.exists(path):
        if tomllib is None:
            raise RuntimeError("TOML parser not available. Install tomli or use Python 3.11+.")
        with open(path, "rb") as f:
            loaded = tomllib.load(f)
            config = _deep_merge(config, loaded)
        logger.info("Loaded client configuration from %s", path)
    elif path:
        logger.warning("Client config path %s not found, using default configuration", path)

    # Environment variable overrides
    c = config["client"]
    if os.getenv("NOVATUNNEL_SERVER_HOST"):
        c["server_host"] = os.getenv("NOVATUNNEL_SERVER_HOST")
    if os.getenv("NOVATUNNEL_SERVER_PORT"):
        c["server_port"] = int(os.getenv("NOVATUNNEL_SERVER_PORT", "51820"))
    if os.getenv("NOVATUNNEL_SERVER_PUBLIC_KEY"):
        c["server_public_key"] = os.getenv("NOVATUNNEL_SERVER_PUBLIC_KEY")
    if os.getenv("NOVATUNNEL_CLIENT_PRIVATE_KEY"):
        c["private_key"] = os.getenv("NOVATUNNEL_CLIENT_PRIVATE_KEY")

    return config


def save_config(config: dict, path: str) -> None:
    """
    Save configuration dictionary to a TOML file.
    Creates parent directories if necessary.
    """
    parent_dir = os.path.dirname(os.path.abspath(path))
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)

    if tomli_w is not None:
        with open(path, "wb") as f:
            tomli_w.dump(config, f)
    else:
        toml_str = _simple_dump_toml(config)
        with open(path, "w", encoding="utf-8") as f:
            f.write(toml_str)

    logger.info("Saved configuration to %s", path)
