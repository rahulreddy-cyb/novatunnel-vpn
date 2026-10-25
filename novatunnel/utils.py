"""
NovaTunnel VPN - System Utilities & Networking
Handles routing tables, NAT/iptables configuration, IP forwarding, and formatting.
"""

import ipaddress
import logging
import os
import platform
import re
import subprocess
import sys
from typing import List, Optional, Tuple

logger = logging.getLogger("novatunnel.utils")


def setup_logging(level: int = logging.INFO) -> None:
    """Configure structured logging for NovaTunnel components."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def run_command(args: List[str], check: bool = True) -> str:
    """
    Execute a shell/system command and return its stdout.

    Args:
        args: List of command arguments.
        check: If True, raise CalledProcessError on non-zero exit.

    Returns:
        Stripped stdout string.
    """
    cmd_str = " ".join(args)
    logger.debug("Executing command: %s", cmd_str)
    try:
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=check,
        )
        return proc.stdout.strip()
    except subprocess.CalledProcessError as e:
        logger.error("Command failed: %s | Error: %s", cmd_str, e.stderr.strip())
        if check:
            raise
        return ""
    except FileNotFoundError as e:
        logger.error("Executable not found for command: %s (%s)", cmd_str, e)
        if check:
            raise
        return ""


def enable_ip_forwarding() -> None:
    """Enable IPv4 forwarding on the Linux host."""
    if platform.system() != "Linux":
        logger.warning("IP forwarding configuration is only supported natively on Linux.")
        return

    forward_path = "/proc/sys/net/ipv4/ip_forward"
    try:
        if os.path.exists(forward_path):
            with open(forward_path, "w") as f:
                f.write("1\n")
            logger.info("Enabled IPv4 forwarding via %s", forward_path)
            return
    except PermissionError:
        logger.warning("No permission to write directly to %s; trying sysctl...", forward_path)

    try:
        run_command(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
        logger.info("Enabled IPv4 forwarding via sysctl")
    except Exception as e:
        logger.error("Failed to enable IP forwarding: %s", e)


def get_default_interface() -> str:
    """
    Determine the primary default outbound network interface name.
    
    Returns:
        Interface name string (e.g. 'eth0', 'ens3', 'wlan0').
    """
    if platform.system() != "Linux":
        return "eth0"

    try:
        output = run_command(["ip", "route", "show", "default"], check=False)
        # Expected output format: 'default via 192.168.1.1 dev eth0 proto dhcp ...'
        match = re.search(r"dev\s+(\S+)", output)
        if match:
            return match.group(1)
    except Exception as e:
        logger.warning("Error detecting default interface via ip route: %s", e)

    return "eth0"


def get_default_route() -> str:
    """
    Return the current default gateway and interface.
    
    Returns:
        String representing default route (e.g., 'via 192.168.1.1 dev eth0').
    """
    if platform.system() != "Linux":
        return ""

    try:
        output = run_command(["ip", "route", "show", "default"], check=False)
        lines = [line.strip() for line in output.splitlines() if line.startswith("default")]
        if lines:
            return lines[0]
    except Exception as e:
        logger.warning("Error getting default route: %s", e)
    return ""


def restore_default_route(route: str) -> None:
    """Restore a previously saved default route string."""
    if not route or platform.system() != "Linux":
        return

    try:
        # Check if route already starts with 'default'
        args = ["ip", "route", "replace"] + route.split()
        run_command(args, check=False)
        logger.info("Restored default route: %s", route)
    except Exception as e:
        logger.error("Failed to restore default route '%s': %s", route, e)


def setup_nat(outbound_interface: str, vpn_subnet: str, tun_name: str = "nova0") -> None:
    """
    Configure iptables rules for NAT/masquerading and VPN packet forwarding.

    Args:
        outbound_interface: Outbound physical interface (e.g. eth0).
        vpn_subnet: VPN CIDR (e.g. 10.8.0.0/24).
        tun_name: Name of TUN interface (e.g. nova0).
    """
    if platform.system() != "Linux":
        logger.info("NAT configuration skipped (non-Linux platform: %s)", platform.system())
        return

    enable_ip_forwarding()

    rules = [
        ["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", vpn_subnet, "-o", outbound_interface, "-j", "MASQUERADE"],
        ["iptables", "-A", "FORWARD", "-i", tun_name, "-o", outbound_interface, "-j", "ACCEPT"],
        ["iptables", "-A", "FORWARD", "-i", outbound_interface, "-o", tun_name, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
    ]

    for rule in rules:
        try:
            run_command(rule, check=False)
            logger.debug("Applied iptables rule: %s", " ".join(rule))
        except Exception as e:
            logger.warning("Could not apply iptables rule %s: %s", rule, e)

    logger.info("Configured NAT and forwarding for subnet %s on %s <-> %s", vpn_subnet, tun_name, outbound_interface)


def teardown_nat(outbound_interface: str, vpn_subnet: str, tun_name: str = "nova0") -> None:
    """Remove iptables rules previously configured by setup_nat."""
    if platform.system() != "Linux":
        return

    rules = [
        ["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", vpn_subnet, "-o", outbound_interface, "-j", "MASQUERADE"],
        ["iptables", "-D", "FORWARD", "-i", tun_name, "-o", outbound_interface, "-j", "ACCEPT"],
        ["iptables", "-D", "FORWARD", "-i", outbound_interface, "-o", tun_name, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
    ]

    for rule in rules:
        try:
            run_command(rule, check=False)
        except Exception:
            pass

    logger.info("Torn down NAT and forwarding rules for %s", tun_name)


def setup_client_routes(
    server_ip: str,
    tun_name: str,
    server_vpn_ip: str,
    vpn_subnet: str = "10.8.0.0/24",
    route_all: bool = True,
) -> Optional[Tuple[str, str]]:
    """
    Configure client routing tables.
    If route_all is True, redirects 0.0.0.0/1 and 128.0.0.0/1 via TUN
    while keeping the route to the VPN server's physical IP via the original default gateway.
    
    Returns:
        Tuple of (original_gateway, original_interface) or None.
    """
    if platform.system() != "Linux":
        logger.warning("Client route management is only natively automated on Linux.")
        return None

    try:
        # Find default gateway
        default_out = run_command(["ip", "route", "show", "default"], check=False)
        gw_match = re.search(r"default via (\S+) dev (\S+)", default_out)
        orig_gw = gw_match.group(1) if gw_match else None
        orig_dev = gw_match.group(2) if gw_match else get_default_interface()

        # 1. Add specific host route to VPN server via original gateway
        if orig_gw and server_ip and server_ip not in ("127.0.0.1", "localhost"):
            run_command(["ip", "route", "add", server_ip, "via", orig_gw, "dev", orig_dev], check=False)

        # 2. Add route for VPN subnet via TUN
        run_command(["ip", "route", "add", vpn_subnet, "dev", tun_name], check=False)

        # 3. If routing all traffic, use the two /1 routes (standard WireGuard/OpenVPN approach)
        if route_all:
            run_command(["ip", "route", "add", "0.0.0.0/1", "dev", tun_name], check=False)
            run_command(["ip", "route", "add", "128.0.0.0/1", "dev", tun_name], check=False)
            logger.info("Full tunnel routing activated via %s", tun_name)

        return (orig_gw or "", orig_dev)
    except Exception as e:
        logger.error("Error setting up client routes: %s", e)
        return None


def teardown_client_routes(
    server_ip: str,
    tun_name: str,
    orig_gw: str,
    orig_dev: str,
    vpn_subnet: str = "10.8.0.0/24",
    route_all: bool = True,
) -> None:
    """Tear down client routes and restore original default routing."""
    if platform.system() != "Linux":
        return

    try:
        if route_all:
            run_command(["ip", "route", "del", "0.0.0.0/1", "dev", tun_name], check=False)
            run_command(["ip", "route", "del", "128.0.0.0/1", "dev", tun_name], check=False)

        run_command(["ip", "route", "del", vpn_subnet, "dev", tun_name], check=False)

        if orig_gw and server_ip:
            run_command(["ip", "route", "del", server_ip, "via", orig_gw, "dev", orig_dev], check=False)

        logger.info("Client routes cleaned up")
    except Exception as e:
        logger.warning("Error cleaning up client routes: %s", e)


def allocate_ip(subnet: str, taken: List[str]) -> str:
    """
    Allocate the next available IPv4 address from subnet that is not in taken list.
    Skips network address and .1 (server address).
    """
    net = ipaddress.ip_network(subnet, strict=False)
    taken_set = set(taken)
    hosts = list(net.hosts())

    if len(hosts) <= 1:
        raise ValueError(f"Subnet {subnet} does not have enough hosts")

    for host in hosts[1:]:
        ip_str = str(host)
        if ip_str not in taken_set:
            return ip_str

    raise RuntimeError(f"No free IP addresses available in subnet {subnet}")


def format_bytes(num_bytes: int) -> str:
    """Format byte count into human-readable representation."""
    if num_bytes < 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    val = float(num_bytes)
    unit_idx = 0
    while val >= 1024.0 and unit_idx < len(units) - 1:
        val /= 1024.0
        unit_idx += 1
    if unit_idx == 0:
        return f"{int(val)} B"
    return f"{val:.2f} {units[unit_idx]}"


def format_uptime(seconds: float) -> str:
    """Format elapsed seconds into human readable duration string."""
    secs = int(max(0, seconds))
    days, secs = divmod(secs, 86400)
    hours, secs = divmod(secs, 3600)
    minutes, secs = divmod(secs, 60)
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0 or days > 0:
        parts.append(f"{hours}h")
    if minutes > 0 or hours > 0 or days > 0:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")
    return " ".join(parts)
