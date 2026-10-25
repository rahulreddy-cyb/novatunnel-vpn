"""
NovaTunnel VPN - Client Command-Line Interface
CLI entry point for connecting to a NovaTunnel VPN server and managing client credentials.
"""

import asyncio
import os
import sys
import click

from novatunnel import crypto
from novatunnel.client import run_client
from novatunnel.config import load_client_config
from novatunnel.utils import setup_logging


@click.group()
@click.version_option(version="1.0.0", prog_name="novatunnel-client")
def cli():
    """NovaTunnel VPN Client CLI"""
    pass


@cli.command("connect")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=False, dir_okay=False),
    default="client.toml",
    show_default=True,
    help="Path to client TOML configuration file",
)
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose debug logging")
def connect_cmd(config_path: str, verbose: bool):
    """Establish an encrypted tunnel connection to a NovaTunnel VPN server."""
    import logging
    setup_logging(level=logging.DEBUG if verbose else logging.INFO)

    click.secho("==================================================", fg="cyan", bold=True)
    click.secho("         NovaTunnel VPN Client v1.0.0            ", fg="cyan", bold=True)
    click.secho("   Secure Encrypted ChaCha20-Poly1305 Tunnel      ", fg="blue")
    click.secho("==================================================", fg="cyan", bold=True)

    if not os.path.exists(config_path):
        click.secho(f"Configuration file '{config_path}' not found.", fg="red", err=True)
        sys.exit(1)

    cfg = load_client_config(config_path)

    try:
        asyncio.run(run_client(cfg))
    except KeyboardInterrupt:
        click.secho("\nClient disconnection requested by user.", fg="yellow")
    except Exception as e:
        click.secho(f"\nClient error: {e}", fg="red", err=True)
        sys.exit(1)


@cli.command("genkey")
def genkey_cmd():
    """Generate a new X25519 keypair for the client."""
    priv, pub = crypto.generate_keypair()
    priv_hex = crypto.key_to_hex(priv)
    pub_hex = crypto.key_to_hex(pub)

    click.echo("")
    click.secho("Client Private Key: ", fg="cyan", nl=False, bold=True)
    click.echo(priv_hex)
    click.secho("Client Public Key:  ", fg="green", nl=False, bold=True)
    click.echo(pub_hex)
    click.echo("")


@cli.command("status")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=False, dir_okay=False),
    default="client.toml",
    help="Path to client configuration",
)
def status_cmd(config_path: str):
    """Display connection parameters for the local configuration."""
    if not os.path.exists(config_path):
        click.secho(f"Config file '{config_path}' does not exist.", fg="red")
        return

    cfg = load_client_config(config_path).get("client", {})
    click.secho("--- NovaTunnel Client Config ---", fg="cyan", bold=True)
    click.echo(f"  Target Server:  {cfg.get('server_host')}:{cfg.get('server_port')}")
    click.echo(f"  Assigned IP:    {cfg.get('assigned_ip') or 'Dynamic (auto)'}")
    click.echo(f"  TUN Device:     {cfg.get('tun_name')}")
    click.echo(f"  Route All:      {cfg.get('route_all_traffic')}")
    click.echo(f"  Client PubKey:  {cfg.get('public_key')}")


def main():
    cli()


if __name__ == "__main__":
    main()
