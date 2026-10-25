"""
NovaTunnel VPN - Server Command-Line Interface
CLI entry point for running the VPN server daemon, provisioning peers, and generating keys.
"""

import asyncio
import os
import sys
import click

from novatunnel import crypto
from novatunnel.config import load_server_config, save_config
from novatunnel.peer import PeerRegistry
from novatunnel.server import run_server
from novatunnel.utils import format_bytes, setup_logging


@click.group()
@click.version_option(version="1.0.0", prog_name="novatunnel-server")
def cli():
    """NovaTunnel VPN Server Management CLI"""
    pass


@cli.command("start")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=False, dir_okay=False),
    default="/etc/novatunnel/server.toml",
    show_default=True,
    help="Path to server TOML configuration file",
)
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose debug logging")
def start_cmd(config_path: str, verbose: bool):
    """Start the NovaTunnel VPN server daemon and Web Dashboard."""
    import logging
    setup_logging(level=logging.DEBUG if verbose else logging.INFO)
    click.secho("==================================================", fg="cyan", bold=True)
    click.secho("         NovaTunnel VPN Server v1.0.0            ", fg="cyan", bold=True)
    click.secho("  ChaCha20-Poly1305 + X25519 Ephemeral Handshake ", fg="blue")
    click.secho("==================================================", fg="cyan", bold=True)

    if not os.path.exists(config_path):
        click.secho(f"Warning: Configuration file '{config_path}' not found.", fg="yellow")
        click.secho("Using defaults with environment variables.", fg="yellow")

    cfg = load_server_config(config_path if os.path.exists(config_path) else None)

    try:
        asyncio.run(run_server(cfg))
    except KeyboardInterrupt:
        click.secho("\nServer shutdown initiated by user.", fg="yellow")
    except Exception as e:
        click.secho(f"\nFatal server error: {e}", fg="red", err=True)
        sys.exit(1)


@cli.command("genkey")
def genkey_cmd():
    """Generate a new X25519 keypair for server or client."""
    priv, pub = crypto.generate_keypair()
    priv_hex = crypto.key_to_hex(priv)
    pub_hex = crypto.key_to_hex(pub)

    click.echo("")
    click.secho("Private Key: ", fg="cyan", nl=False, bold=True)
    click.echo(priv_hex)
    click.secho("Public Key:  ", fg="green", nl=False, bold=True)
    click.echo(pub_hex)
    click.echo("")


@cli.command("add-peer")
@click.option("-n", "--name", required=True, help="Friendly name or identifier for the peer")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=False, dir_okay=False),
    default="/etc/novatunnel/server.toml",
    show_default=True,
    help="Path to server TOML configuration file",
)
@click.option("--ip", "assigned_ip", default=None, help="Specific VPN IP to assign (e.g. 10.8.0.5)")
@click.option("-o", "--out", "out_file", type=click.Path(dir_okay=False), default=None, help="File to write client.toml into")
def add_peer_cmd(name: str, config_path: str, assigned_ip: str, out_file: str):
    """Add a new VPN peer, generate cryptographic keys, and generate client configuration."""
    cfg = load_server_config(config_path if os.path.exists(config_path) else None)
    server_cfg = cfg.get("server", {})
    peers_file = server_cfg.get("peers_file", "/etc/novatunnel/peers.json")
    vpn_subnet = server_cfg.get("vpn_subnet", "10.8.0.0/24")

    registry = PeerRegistry(storage_path=peers_file)

    # Generate client keypair
    c_priv, c_pub = crypto.generate_keypair()
    c_priv_hex = crypto.key_to_hex(c_priv)
    c_pub_hex = crypto.key_to_hex(c_pub)

    try:
        peer = registry.add_peer(
            name=name,
            public_key_hex=c_pub_hex,
            assigned_ip=assigned_ip,
            subnet=vpn_subnet,
        )
    except Exception as e:
        click.secho(f"Failed to add peer: {e}", fg="red", err=True)
        sys.exit(1)

    server_host = server_cfg.get("host", "127.0.0.1")
    if server_host == "0.0.0.0":
        server_host = "YOUR_SERVER_PUBLIC_IP"
    server_port = server_cfg.get("port", 51820)
    server_pub = server_cfg.get("public_key", "")
    dns_list = server_cfg.get("dns", ["1.1.1.1", "8.8.8.8"])
    dns_str = ", ".join(f'"{d}"' for d in dns_list)

    client_toml = f"""# NovaTunnel Client Configuration for {peer.name}
# Peer ID: {peer.peer_id}

[client]
server_host = "{server_host}"
server_port = {server_port}
server_public_key = "{server_pub}"
private_key = "{c_priv_hex}"
public_key = "{c_pub_hex}"
assigned_ip = "{peer.assigned_ip}"
tun_name = "nova-client"
mtu = 1420
keepalive_interval = 25
route_all_traffic = true
dns = [{dns_str}]
"""

    click.secho(f"Peer '{peer.name}' added successfully!", fg="green", bold=True)
    click.echo(f"  Peer ID:     {peer.peer_id}")
    click.echo(f"  Assigned IP: {peer.assigned_ip}")
    click.echo(f"  Public Key:  {peer.public_key_hex}")

    if out_file:
        os.makedirs(os.path.dirname(os.path.abspath(out_file)), exist_ok=True)
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(client_toml)
        click.secho(f"\nClient configuration written to: {out_file}", fg="cyan")
    else:
        click.secho("\n--- Client Configuration (client.toml) ---", fg="cyan")
        click.echo(client_toml)
        click.secho("------------------------------------------", fg="cyan")


@cli.command("list-peers")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=False, dir_okay=False),
    default="/etc/novatunnel/server.toml",
    show_default=True,
    help="Path to server TOML configuration file",
)
def list_peers_cmd(config_path: str):
    """Display a table of all registered VPN peers."""
    cfg = load_server_config(config_path if os.path.exists(config_path) else None)
    peers_file = cfg.get("server", {}).get("peers_file", "/etc/novatunnel/peers.json")
    registry = PeerRegistry(storage_path=peers_file)
    peers = registry.list_peers()

    if not peers:
        click.echo("No peers registered yet.")
        return

    click.echo("")
    header = f"{'NAME':<16} {'VPN IP':<15} {'STATUS':<12} {'TX BYTES':<12} {'RX BYTES':<12} {'PUBLIC KEY':<16}"
    click.secho(header, fg="cyan", bold=True)
    click.secho("-" * len(header), fg="slate" if "slate" in click.termui._ansi_colors else "blue")

    for p in peers:
        status = "CONNECTED" if p.is_connected else "IDLE"
        pub_snippet = f"{p.public_key_hex[:6]}...{p.public_key_hex[-6:]}" if len(p.public_key_hex) >= 12 else p.public_key_hex
        line = f"{p.name:<16} {p.assigned_ip:<15} {status:<12} {format_bytes(p.bytes_sent):<12} {format_bytes(p.bytes_recv):<12} {pub_snippet:<16}"
        if p.is_connected:
            click.secho(line, fg="green")
        else:
            click.echo(line)
    click.echo("")


@cli.command("remove-peer")
@click.argument("peer_id")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=False, dir_okay=False),
    default="/etc/novatunnel/server.toml",
    show_default=True,
    help="Path to server TOML configuration file",
)
def remove_peer_cmd(peer_id: str, config_path: str):
    """Remove a peer from the server registry by its UUID."""
    cfg = load_server_config(config_path if os.path.exists(config_path) else None)
    peers_file = cfg.get("server", {}).get("peers_file", "/etc/novatunnel/peers.json")
    registry = PeerRegistry(storage_path=peers_file)

    if registry.remove_peer(peer_id):
        click.secho(f"Peer '{peer_id}' removed successfully.", fg="green")
    else:
        click.secho(f"Peer '{peer_id}' not found.", fg="red", err=True)
        sys.exit(1)


def main():
    cli()


if __name__ == "__main__":
    main()
