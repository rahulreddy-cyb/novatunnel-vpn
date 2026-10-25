# NovaTunnel VPN

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://www.kernel.org/)
[![Encryption](https://img.shields.io/badge/cipher-ChaCha20--Poly1305-green.svg)](https://datatracker.ietf.org/doc/html/rfc8439)
[![Key Exchange](https://img.shields.io/badge/key%20exchange-X25519%20ECDH-orange.svg)](https://datatracker.ietf.org/doc/html/rfc7748)

**NovaTunnel** is an experimental Virtual Private Network (VPN) project built in Python. It features a custom lightweight binary UDP encapsulation protocol, **ChaCha20-Poly1305** authenticated encryption (AEAD), **X25519 ECDH** ephemeral key agreement, real Linux **TUN interface** routing, and an integrated real-time web management dashboard.

Unlike simple SOCKS/HTTP proxies or TLS tunnels, NovaTunnel is a **true Layer 3 (Network Layer) VPN**. It captures raw IP datagrams, encrypts them, routes them over an authenticated UDP tunnel, and is intended to provide bidirectional IP connectivity.

---

## Project Status
**Status: Experimental | Security Testing in Progress**

NovaTunnel VPN is a Python-based networking and
cybersecurity project developed for learning, research,
and controlled lab testing.

### Key Components
- Python VPN client and server
- Linux TUN network interfaces
- X25519 key exchange
- ChaCha20-Poly1305 encryption
- UDP-based VPN communication
- Flask web management dashboard
- Docker and systemd deployment support

### Security Notice

This project has not undergone an independent security
audit. Encryption, authentication, routing, and traffic
leak protections require further validation.

NovaTunnel is not recommended for protecting sensitive
production traffic at this stage.


---

## Architecture Diagram

```
 +-------------------------------------------------------------------------------+
 |                                 CLIENT HOST                                   |
 |  [Applications] -> (Kernel IP Stack) -> [TUN: nova-client (10.8.0.2)]         |
 |                                                      |                        |
 |                                           [NovaTunnel Client Engine]          |
 |                                           - ChaCha20-Poly1305 AEAD            |
 |                                           - 12-byte CSPRNG Nonce              |
 +------------------------------------------------------|------------------------+
                                                        |
                                          UDP Encapsulated Datagrams
                                            (Port 51820 / ChaCha20)
                                                        |
 +------------------------------------------------------|------------------------+
 |                                                      v                        |
 |                                           [NovaTunnel Server Engine]          |
 |                                           - Session Registry (ECDH)           |
 |                                           - Packet Decryption & Routing       |
 |                                                      |                        |
 |  [Flask Dashboard] <---> [Peer DB] <---> [TUN: nova0 (10.8.0.1)]              |
 |                                                      |                        |
 |                                          (Kernel NAT / MASQUERADE)            |
 |                                                      |                        |
 |                                                 [eth0 / ens3]                 |
 |                                 SERVER HOST          |                        |
 +------------------------------------------------------|------------------------+
                                                        v
                                                 (( INTERNET ))
```

---

## Features

- [x] **Cryptographic Components**: X25519 Elliptic Curve Diffie-Hellman key exchange combined with ChaCha20-Poly1305 AEAD (RFC 8439) encryption and HKDF-SHA256 key derivation.
- [x] **Real Layer 3 TUN Device**: Interacts directly with Linux `/dev/net/tun` for native IPv4 datagram capture and transmission.
- [x] **Custom Binary Protocol**: 16-byte fixed header with big-endian serialization and sequence tracking.
- [x] **Full-Tunnel IPv4 Routing**: Supports redirecting IPv4 traffic through the VPN. DNS and IPv6 leak protection remain unverified.
- [x] **Session Key Agreement**: Implements session key negotiation. Forward secrecy has not been independently verified.
- [x] **NAT Traversal & Dynamic Roaming**: Endpoint tracking automatically accommodates client IP and port changes without interrupting connections.
- [x] **Automatic IP Pool Management**: Dynamic DHCP-like IP allocation for connecting clients within configurable subnets (default `10.8.0.0/24`).
- [x] **Integrated Web Dashboard**: Dark-themed UI crafted with Tailwind CSS featuring real-time peer metrics, traffic graphs, active session management, and configuration downloads.
- [x] **Deployment Tools**: Includes systemd services, Docker, Docker Compose, and an installer. Production hardening is still required.

---

## Protocol Specification

NovaTunnel datagrams sent over UDP follow this binary structure:

### 1. Packet Header Format (16 Bytes)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Type (1 Byte)|             Session ID (4 Bytes)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Session ID (cont.)      |     Sequence Number (4 Bytes) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Sequence Number (cont.)     |       Timestamp (4 Bytes)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Timestamp (cont.)      |        Flags (3 Bytes)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Payload (Variable Length: Nonce [12B] + Ciphertext + Tag) ... |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Size | Description |
|---|---|---|
| **Packet Type** | 1 Byte | `1` = `HANDSHAKE_INIT`, `2` = `HANDSHAKE_RESP`, `3` = `DATA`, `4` = `KEEPALIVE`, `5` = `DISCONNECT` |
| **Session ID** | 4 Bytes (uint32) | Random non-zero session identifier negotiated during handshake |
| **Sequence Number** | 4 Bytes (uint32) | Incremental counter for replay detection |
| **Timestamp** | 4 Bytes (uint32) | Epoch timestamp in seconds |
| **Flags** | 3 Bytes | Reserved for future capabilities (congestion, QoS) |
| **Payload** | Variable | For DATA: 12-byte random nonce + ChaCha20 ciphertext + 16-byte Poly1305 MAC |

### 2. Handshake Negotiation Sequence

```
Client                                                   Server
  |                                                        |
  | -------- HANDSHAKE_INIT (Client PubKey: 32B) --------> |
  |                                                        | (Derives shared secret via ECDH)
  |                                                        | (Allocates VPN IP 10.8.0.X)
  |                                                        | (Encrypts JSON config)
  | <------- HANDSHAKE_RESP (Server PubKey + EncConfig) -- |
  |                                                        |
(Derives shared secret)                                    |
(Decrypts config & configures TUN)                         |
  |                                                        |
  | <================ Bi-directional Encrypted DATA =====> |
  |                                                        |
  | -------- KEEPALIVE (Every 25 seconds) ---------------> |
  | <------- KEEPALIVE Ack ------------------------------- |
```

---

## Quick Start with Docker

You can spin up an entire NovaTunnel VPN server with Docker in 5 simple commands:

```bash
# 1. Clone the repository
git clone https://github.com/rahulreddy-cyb/novatunnel-vpn.git
cd novatunnel-vpn

# 2. Copy the sample environment configuration
cp .env.example .env

# 3. Build and launch the container with NET_ADMIN privileges
docker compose up -d --build

# 4. View server logs and verify operation
docker compose logs -f novatunnel

# 5. Access the Web Dashboard in your browser
# Open: http://YOUR_SERVER_IP:8080 (configure unique credentials and restrict dashboard access before use)
```

---

## Manual Installation (Ubuntu / Debian)

For native performance without Docker virtualization, use the automated installer:

```bash
# Download and execute the automated setup script as root
sudo bash install.sh
```

The script will automatically:
1. Install Python 3, `iproute2`, and `iptables`.
2. Provision an isolated virtual environment in `/opt/novatunnel/venv`.
3. Generate cryptographically strong server X25519 keys.
4. Enable Linux IPv4 kernel forwarding (`net.ipv4.ip_forward = 1`).
5. Configure the systemd daemon `novatunnel-server.service` and start the VPN.
6. Display your public key and web dashboard credentials.

---

## Server Configuration Reference

Configurations are stored in `/etc/novatunnel/server.toml`:

```toml
[server]
host = "0.0.0.0"                      # UDP listening address
port = 51820                          # UDP listening port
private_key = "<64-hex-chars>"        # Server X25519 private key
public_key = "<64-hex-chars>"         # Server X25519 public key
vpn_subnet = "10.8.0.0/24"            # Virtual IP subnet
server_vpn_ip = "10.8.0.1"            # Gateway IP inside tunnel
tun_name = "nova0"                    # Virtual TUN device name
mtu = 1420                            # Maximum transmission unit
dns = ["1.1.1.1", "8.8.8.8"]          # DNS servers pushed to clients
max_peers = 50                        # Concurrent peer threshold
peers_file = "/etc/novatunnel/peers.json" # Persistent peer registry

[dashboard]
enabled = true                        # Toggle web dashboard
host = "0.0.0.0"                      # HTTP bind interface
port = 8080                           # HTTP dashboard port
secret_key = "<random-secret>"        # Flask session key
username = "admin"                    # Dashboard username
password = "admin_secure_password"   # Dashboard password
```

---

## Client Setup & Workflow

### 1. Provision a New Client on Server

Using the CLI:
```bash
novatunnel-server add-peer --name alice-laptop --out /tmp/alice.toml
```

Or visit the Web Dashboard at `http://YOUR_SERVER_IP:8080`, navigate to **Peers**, click **Add New Peer**, and download `client.toml`.

### 2. Connect from Client Device

Install the package on the client machine:
```bash
pip install -e .
```

Initiate the secure connection:
```bash
sudo novatunnel-client connect --config alice.toml
```

Check configuration parameters:
```bash
novatunnel-client status --config alice.toml
```

To disconnect, simply press `Ctrl+C`. The client will automatically notify the server with a `DISCONNECT` datagram and restore the host's original default routing tables and DNS.

---

## Web Management Dashboard

NovaTunnel includes an integrated, responsive dashboard:
- **Server Health Card**: Live daemon heartbeat, uptime timer, and UDP listener status.
- **Peer Overview**: Instant overview of connected clients, dynamic remote IP:port endpoints, and active session keys.
- **Bandwidth Tracking**: Live counters of uploaded (Tx) and downloaded (Rx) bytes.
- **One-Click Provisioning**: Interactive modal to create peers, generate X25519 keypairs, preview `client.toml`, and download configs instantly.
- **Real-Time Polling**: Auto-refreshes metrics without page reloads using the `/api/status` endpoint.

---

## Security Considerations

1. **Authenticated Encryption**: Every data packet uses ChaCha20-Poly1305. Any alteration, tampering, or bit-flipping immediately causes an authentication tag verification failure and packet discard.
2. **Replay Protection**: Packets contain sequential sequence numbers and timestamps.
3. **No Key Reuse**: Handshakes generate fresh ephemeral X25519 keys per session. Even if an attacker records encrypted traffic, compromising long-term keys does not decrypt past sessions.
4. **Linux Capabilities**: When running natively or in Docker, the daemon only requires `CAP_NET_ADMIN` and `CAP_NET_RAW` to manage virtual network adapters and routing tables.
5. **Dashboard Hardening**: In production, change the default dashboard credentials in `server.toml` or set `NOVATUNNEL_DASHBOARD_PASS` via environment variables. For public deployments, place a reverse proxy (e.g. Nginx or Caddy) with TLS in front of the dashboard.

---

## Troubleshooting

### Common Issue: `PermissionError: Root/CAP_NET_ADMIN privilege required to open /dev/net/tun`
- **Solution**: Creating virtual TUN interfaces requires Linux network administrator privileges. Run the server or client with `sudo` or grant `cap_net_admin` capability:
  ```bash
  sudo setcap cap_net_admin,cap_net_raw+eip $(which python3)
  ```

### Common Issue: Clients connect but cannot access the Internet
- **Solution**: Ensure IPv4 forwarding and NAT are enabled on the server:
  ```bash
  sudo sysctl -w net.ipv4.ip_forward=1
  sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
  ```

### Common Issue: UDP traffic blocked by firewall
- **Solution**: Open UDP port 51820 on your host firewall or cloud security group (AWS, GCP, DigitalOcean):
  ```bash
  sudo ufw allow 51820/udp
  sudo ufw allow 8080/tcp
  ```

---

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on GitHub:
1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## License

Distributed under the **MIT License**. See `LICENSE` for details.
