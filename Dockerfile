FROM python:3.11-slim

LABEL maintainer="NovaTunnel Team"
LABEL description="NovaTunnel VPN Server with ChaCha20-Poly1305 and X25519"

# Install essential Linux network tools and kernel interface utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iptables \
    procps \
    net-tools \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first for caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and install NovaTunnel package
COPY . .
RUN pip install --no-cache-dir -e .

# Create configuration and data directories
RUN mkdir -p /etc/novatunnel /var/lib/novatunnel

# Expose VPN UDP tunnel port and Web Dashboard HTTP port
EXPOSE 51820/udp 8080/tcp

ENTRYPOINT ["novatunnel-server"]
CMD ["start", "--config", "/etc/novatunnel/server.toml"]
