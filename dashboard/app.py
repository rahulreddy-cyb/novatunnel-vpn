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
import threading
import math
from functools import wraps
from datetime import timedelta
from urllib.parse import unquote, urlsplit
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

from flask_wtf.csrf import CSRFProtect

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
            return redirect(url_for("login", next=request.full_path.rstrip("?")))
        return f(*args, **kwargs)
    return decorated_function



def _safe_next_path(target):
    """Allow only local absolute-path redirects after login."""
    if not isinstance(target, str) or not target.startswith("/"):
        return url_for("index")

    decoded = unquote(target)
    parsed = urlsplit(decoded)

    if (
        decoded.startswith("//")
        or "\\" in decoded
        or parsed.scheme
        or parsed.netloc
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in decoded)
    ):
        return url_for("index")

    return target


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

    dashboard_secret = cfg_dash.get("secret_key")
    admin_user = cfg_dash.get("username")
    admin_pass = cfg_dash.get("password")

    if (
        not isinstance(dashboard_secret, str)
        or len(dashboard_secret) < 32
        or dashboard_secret == "change-me-in-production-novatunnel"
    ):
        raise RuntimeError(
            "Configure a strong NOVATUNNEL_DASHBOARD_SECRET"
        )

    if not isinstance(admin_user, str) or not admin_user.strip():
        raise RuntimeError("Configure NOVATUNNEL_DASHBOARD_USER")

    if (
        not isinstance(admin_pass, str)
        or len(admin_pass) < 12
        or admin_pass == "admin"
    ):
        raise RuntimeError(
            "Configure a strong NOVATUNNEL_DASHBOARD_PASS"
        )

    app.secret_key = dashboard_secret

    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        SESSION_REFRESH_EACH_REQUEST=False,
    )

    CSRFProtect(app)

    # Initialize or link registry
    if registry is None:
        peers_file = cfg_server.get("peers_file", "/etc/novatunnel/peers.json")
        reg = PeerRegistry(storage_path=peers_file)
    else:
        reg = registry

    @app.after_request
    def protect_provisioning_responses(response):
        if request.endpoint in {
            "peers_add",
            "peers_config",
            "peers_qrcode",
        }:
            response.headers["Cache-Control"] = "no-store, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.context_processor
    def inject_global_vars():
        return {
            "uptime_str": format_uptime(time.time() - START_TIME),
            "version": "1.0.0",
        }

    # Single-process login throttling prototype.
    login_failures = {}
    login_blocked_until = {}
    login_attempts_lock = threading.Lock()

    def login_retry_after(addr):
        now = time.monotonic()
        with login_attempts_lock:
            until = login_blocked_until.get(addr, 0)
            if until > now:
                return max(1, math.ceil(until - now))
            login_blocked_until.pop(addr, None)
        return 0

    def record_failed_login(addr):
        now = time.monotonic()
        with login_attempts_lock:
            attempts = [
                t for t in login_failures.get(addr, [])
                if now - t < 300
            ]
            attempts.append(now)

            if len(attempts) >= 5:
                login_blocked_until[addr] = now + 900
                login_failures.pop(addr, None)
            else:
                login_failures[addr] = attempts

    def clear_failed_logins(addr):
        with login_attempts_lock:
            login_failures.pop(addr, None)
            login_blocked_until.pop(addr, None)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        """User login page and credential verification."""
        error = None
        if request.method == "POST":
            client_ip = request.remote_addr or "unknown"
            retry_after = login_retry_after(client_ip)

            if retry_after:
                return (
                    render_template(
                        "login.html",
                        error="Too many login attempts. Try again later."
                    ),
                    429,
                    {"Retry-After": str(retry_after)},
                )

            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()

            if secrets.compare_digest(username, admin_user) and secrets.compare_digest(password, admin_pass):
                clear_failed_logins(client_ip)
                session.clear()
                session.permanent = True
                session["logged_in"] = True
                session["username"] = username
                next_page = _safe_next_path(request.args.get("next"))
                return redirect(next_page)
            else:
                record_failed_login(client_ip)
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
        if not request.is_json:
            return jsonify({
                "success": False,
                "error": "JSON provisioning required",
            }), 415

        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({
                "success": False,
                "error": "Invalid JSON payload",
            }), 400
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
            client_config_str = generate_client_toml(peer, client_priv_hex, cfg_server)

            response = jsonify({
                "success": True,
                "peer": peer.to_dict(),
                "client_public_key": client_pub_hex,
                "config_toml": client_config_str,
            })
            response.headers["Cache-Control"] = "no-store"
            return response
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
        """Private keys cannot be retrieved after provisioning."""
        if reg.get_by_id(peer_id) is None:
            abort(404)
        abort(410, description=(
            "Client configuration was available only during "
            "provisioning. Reprovision the peer if it was lost."
        ))

    @app.route("/peers/<peer_id>/qrcode")
    @login_required
    def peers_qrcode(peer_id: str):
        """Do not regenerate secret-bearing QR codes."""
        if reg.get_by_id(peer_id) is None:
            abort(404)
        abort(410, description=(
            "Private-key QR codes are no longer retained. "
            "Reprovision the peer if necessary."
        ))

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

    if not isinstance(client_priv_hex, str) or len(client_priv_hex) != 64:
        raise ValueError("A valid 32-byte client private key is required")
    try:
        bytes.fromhex(client_priv_hex)
    except ValueError as exc:
        raise ValueError("Invalid client private key encoding") from exc

    priv_line = client_priv_hex

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
    app.run(host="127.0.0.1", port=8080, debug=False)
