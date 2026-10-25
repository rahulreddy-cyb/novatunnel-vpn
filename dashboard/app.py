"""
NovaTunnel VPN - Flask Web Management Dashboard
Provides web interface and REST API for peer monitoring, configuration generation, and server metrics.
"""

import io
import json
import logging
import os
import secrets
import time
from functools import wraps
from typing import Optional

from flask import (
    Flask,
    Response,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from novatunnel import crypto
from novatunnel.config import load_server_config
from novatunnel.peer import Peer, PeerRegistry
from novatunnel.utils import format_bytes, format_uptime

logger = logging.getLogger("novatunnel.dashboard")
START_TIME = time.time()


def login_required(f):
    """Decorator to enforce session authentication for protected routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def create_app(
    registry: Optional[PeerRegistry] = None,
    server_config: Optional[dict] = None,
) -> Flask:
    """
    Application factory for the NovaTunnel web dashboard.
    
    Args:
        registry: Existing PeerRegistry instance. If None, initialized from config.
        server_config: Dictionary containing server settings. If None, loaded from disk/env.
        
    Returns:
        Configured Flask application instance.
    """
    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
    app = Flask(__name__, template_folder=template_dir)

    full_cfg = load_server_config()
    cfg_server = server_config or full_cfg.get("server", {})
    cfg_dash = full_cfg.get("dashboard", {})

    app.secret_key = cfg_dash.get("secret_key", secrets.token_hex(32))
    admin_user = cfg_dash.get("username", "admin")
    admin_pass = cfg_dash.get("password", "admin")

    # In-memory storage for generated client keys (so clients can download config with their private key)
    # peer_id -> {"private_key_hex": str, "public_key_hex": str}
    client_key_cache = {}

    # Initialize or link registry
    if registry is None:
        peers_file = cfg_server.get("peers_file", "/etc/novatunnel/peers.json")
        reg = PeerRegistry(storage_path=peers_file)
    else:
        reg = registry

    @app.context_processor
    def inject_global_vars():
        return {
            "uptime_str": format_uptime(time.time() - START_TIME),
            "version": "1.0.0",
        }

    @app.route("/login", methods=["GET", "POST"])
    def login():
        """User login page and credential verification."""
        error = None
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()

            if secrets.compare_digest(username, admin_user) and secrets.compare_digest(password, admin_pass):
                session["logged_in"] = True
                session["username"] = username
                next_page = request.args.get("next") or url_for("index")
                return redirect(next_page)
            else:
                error = "Invalid username or password"

        return render_template("login.html", error=error)

    @app.route("/logout")
    def logout():
        """Clear user session and redirect to login."""
        session.clear()
        return redirect(url_for("login"))

    @app.route("/")
    @login_required
    def index():
        """Dashboard overview: server status, statistics, and recent peers."""
        peers = reg.list_peers()
        active_peers = [p for p in peers if p.is_connected]
        total_bytes_sent = sum(p.bytes_sent for p in peers)
        total_bytes_recv = sum(p.bytes_recv for p in peers)
        uptime = format_uptime(time.time() - START_TIME)

        # Sort recent peers by last_seen
        recent_peers = sorted(peers, key=lambda x: x.last_seen, reverse=True)[:5]

        stats = {
            "status": "Online",
            "active_count": len(active_peers),
            "total_count": len(peers),
            "total_sent_fmt": format_bytes(total_bytes_sent),
            "total_recv_fmt": format_bytes(total_bytes_recv),
            "uptime": uptime,
        }

        return render_template(
            "index.html",
            stats=stats,
            recent_peers=recent_peers,
            format_bytes=format_bytes,
            format_uptime=format_uptime,
        )

    @app.route("/peers")
    @login_required
    def peers():
        """Full list of peers and client management actions."""
        all_peers = sorted(reg.list_peers(), key=lambda p: p.name.lower())
        return render_template(
            "peers.html",
            peers=all_peers,
            format_bytes=format_bytes,
            format_uptime=format_uptime,
        )

    @app.route("/peers/add", methods=["POST"])
    @login_required
    def peers_add():
        """Add a new peer, generate client keypair, and return configuration."""
        data = request.get_json(silent=True) or request.form
        peer_name = data.get("name", "").strip() or f"peer-{secrets.token_hex(3)}"
        custom_ip = data.get("assigned_ip", "").strip() or None

        # Generate fresh client keypair
        client_priv, client_pub = crypto.generate_keypair()
        client_priv_hex = crypto.key_to_hex(client_priv)
        client_pub_hex = crypto.key_to_hex(client_pub)

        vpn_subnet = cfg_server.get("vpn_subnet", "10.8.0.0/24")

        try:
            peer = reg.add_peer(
                name=peer_name,
                public_key_hex=client_pub_hex,
                assigned_ip=custom_ip,
                subnet=vpn_subnet,
            )
            # Store generated client private key in cache for download
            client_key_cache[peer.peer_id] = {
                "private_key_hex": client_priv_hex,
                "public_key_hex": client_pub_hex,
            }

            client_config_str = generate_client_toml(peer, client_priv_hex, cfg_server)

            if request.is_json:
                return jsonify({
                    "success": True,
                    "peer": peer.to_dict(),
                    "client_private_key": client_priv_hex,
                    "client_public_key": client_pub_hex,
                    "config_toml": client_config_str,
                })
            else:
                flash(f"Peer '{peer_name}' created successfully!", "success")
                return redirect(url_for("peers"))
        except Exception as e:
            logger.error("Failed to add peer: %s", e)
            if request.is_json:
                return jsonify({"success": False, "error": str(e)}), 400
            flash(f"Failed to create peer: {e}", "error")
            return redirect(url_for("peers"))

    @app.route("/peers/<peer_id>/delete", methods=["POST"])
    @login_required
    def peers_delete(peer_id: str):
        """Delete an existing peer by UUID."""
        success = reg.remove_peer(peer_id)
        client_key_cache.pop(peer_id, None)

        if request.is_json:
            return jsonify({"success": success})
        if success:
            flash("Peer deleted successfully", "success")
        else:
            flash("Peer not found", "error")
        return redirect(url_for("peers"))

    @app.route("/peers/<peer_id>/config")
    @login_required
    def peers_config(peer_id: str):
        """Download client TOML configuration for a peer."""
        peer = reg.get_by_id(peer_id)
        if not peer:
            abort(404, "Peer not found")

        cached = client_key_cache.get(peer_id, {})
        client_priv_hex = cached.get("private_key_hex", "")

        config_str = generate_client_toml(peer, client_priv_hex, cfg_server)
        filename = f"{peer.name.replace(' ', '_')}-novatunnel.toml"

        return Response(
            config_str,
            mimetype="text/plain",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    @app.route("/peers/<peer_id>/qrcode")
    @login_required
    def peers_qrcode(peer_id: str):
        """Generate and stream a QR code image representing the peer configuration."""
        peer = reg.get_by_id(peer_id)
        if not peer:
            abort(404, "Peer not found")

        cached = client_key_cache.get(peer_id, {})
        client_priv_hex = cached.get("private_key_hex", "")
        config_str = generate_client_toml(peer, client_priv_hex, cfg_server)

        try:
            import qrcode
            img = qrcode.make(config_str)
            buf = io.BytesIO()
            img.save(buf, "PNG")
            buf.seek(0)
            return send_file(buf, mimetype="image/png")
        except ImportError:
            return "QR Code generation requires the 'qrcode' and 'Pillow' packages", 501

    # REST APIs
    @app.route("/api/status")
    @login_required
    def api_status():
        """Return server runtime metrics in JSON format."""
        peers = reg.list_peers()
        active = [p for p in peers if p.is_connected]
        total_sent = sum(p.bytes_sent for p in peers)
        total_recv = sum(p.bytes_recv for p in peers)
        elapsed = time.time() - START_TIME

        return jsonify({
            "status": "online",
            "uptime_seconds": elapsed,
            "uptime": format_uptime(elapsed),
            "active_peers": len(active),
            "total_peers": len(peers),
            "bytes_sent": total_sent,
            "bytes_recv": total_recv,
            "bytes_sent_fmt": format_bytes(total_sent),
            "bytes_recv_fmt": format_bytes(total_recv),
        })

    @app.route("/api/peers")
    @login_required
    def api_peers():
        """Return list of peers with metrics."""
        peers = reg.list_peers()
        result = []
        for p in peers:
            d = p.to_dict()
            d["bytes_sent_fmt"] = format_bytes(p.bytes_sent)
            d["bytes_recv_fmt"] = format_bytes(p.bytes_recv)
            d["last_seen_fmt"] = format_uptime(time.time() - p.last_seen) if p.last_seen > 0 else "Never"
            result.append(d)
        return jsonify(result)

    return app


def generate_client_toml(peer: Peer, client_priv_hex: str, server_config: dict) -> str:
    """Generate a clean client TOML configuration text."""
    server_host = server_config.get("host", "127.0.0.1")
    if server_host == "0.0.0.0":
        server_host = "YOUR_SERVER_PUBLIC_IP"
    server_port = server_config.get("port", 51820)
    server_pub_hex = server_config.get("public_key", "")
    dns_list = server_config.get("dns", ["1.1.1.1", "8.8.8.8"])
    dns_formatted = ", ".join(f'"{d}"' for d in dns_list)

    priv_line = client_priv_hex if client_priv_hex else "# Generated separately by client"

    return f"""# NovaTunnel Client Configuration
# Peer: {peer.name} ({peer.peer_id})
# Generated at: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}

[client]
server_host = "{server_host}"
server_port = {server_port}
server_public_key = "{server_pub_hex}"
private_key = "{priv_line}"
public_key = "{peer.public_key_hex}"
assigned_ip = "{peer.assigned_ip}"
tun_name = "nova-client"
mtu = 1420
keepalive_interval = 25
route_all_traffic = true
dns = [{dns_formatted}]
"""


# Standalone application entry
app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True)
