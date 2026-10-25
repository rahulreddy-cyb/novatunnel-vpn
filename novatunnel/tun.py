"""
NovaTunnel VPN - TUN/TAP Virtual Network Interface
Creates and manages virtual network interfaces for capturing and injecting IP packets.
"""

import logging
import os
import platform
import struct
import subprocess
from typing import Optional

logger = logging.getLogger("novatunnel.tun")

# Linux TUN/TAP ioctl constants
TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000


class TunInterface:
    """
    Manages a virtual TUN (Network Layer / Layer 3) interface.
    Primary implementation targets Linux kernel /dev/net/tun with full packet I/O.
    """

    def __init__(self, name: str = "nova0"):
        self.requested_name = name
        self.name = name
        self.fd: Optional[int] = None
        self.is_open = False
        self.local_ip: Optional[str] = None
        self.peer_ip: Optional[str] = None
        self.mtu: int = 1420

    def open(self) -> None:
        """
        Open the TUN device and bind the virtual network interface.
        
        Raises:
            NotImplementedError: If host OS is not Linux.
            PermissionError: If root / CAP_NET_ADMIN privileges are missing.
            OSError: If device /dev/net/tun cannot be opened or configured.
        """
        sys_platform = platform.system()
        if sys_platform != "Linux":
            raise NotImplementedError(
                f"TUN interface is currently supported natively on Linux (detected: {sys_platform}). "
                f"To run NovaTunnel on Windows or macOS, please run inside Docker with --cap-add=NET_ADMIN "
                f"or in a WSL2 / Linux VM."
            )

        tun_device = "/dev/net/tun"
        if not os.path.exists(tun_device):
            raise OSError(f"TUN device '{tun_device}' does not exist. Ensure tun kernel module is loaded.")

        try:
            import fcntl
            self.fd = os.open(tun_device, os.O_RDWR)
            
            # Struct ifreq: 16 bytes name, 2 bytes flags, padded to 40 bytes
            ifr = struct.pack("16sH", self.requested_name.encode("utf-8")[:15], IFF_TUN | IFF_NO_PI)
            ret = fcntl.ioctl(self.fd, TUNSETIFF, ifr)
            
            # The kernel returns the actual allocated interface name in the first 16 bytes
            self.name = ret[:16].decode("utf-8", errors="ignore").strip("\x00")
            self.is_open = True
            logger.info("Successfully opened TUN interface '%s' (fd=%d)", self.name, self.fd)
        except PermissionError as e:
            logger.error("Root or CAP_NET_ADMIN privilege required to open %s", tun_device)
            raise PermissionError(f"Root/CAP_NET_ADMIN privilege required to open {tun_device}: {e}") from e
        except Exception as e:
            logger.error("Failed to initialize TUN interface '%s': %s", self.requested_name, e)
            if self.fd is not None:
                os.close(self.fd)
                self.fd = None
            raise

    def configure(self, local_ip: str, peer_ip: Optional[str] = None, mtu: int = 1420) -> None:
        """
        Assign IP addresses and MTU to the TUN interface.

        Args:
            local_ip: Local VPN IP address (e.g. '10.8.0.1' or '10.8.0.2').
            peer_ip: Optional remote peer/gateway IP (e.g. '10.8.0.1').
            mtu: Maximum Transmission Unit (default: 1420 to prevent UDP fragmentation).
        """
        self.local_ip = local_ip
        self.peer_ip = peer_ip
        self.mtu = mtu

        logger.info("Configuring TUN interface '%s': local=%s, peer=%s, mtu=%d", self.name, local_ip, peer_ip, mtu)

        # Set MTU
        self._exec(["ip", "link", "set", "dev", self.name, "mtu", str(mtu)])

        # Assign IP address
        if peer_ip:
            # Point-to-point interface
            self._exec(["ip", "addr", "add", f"{local_ip}/24", "peer", peer_ip, "dev", self.name])
        else:
            self._exec(["ip", "addr", "add", f"{local_ip}/24", "dev", self.name])

    def up(self) -> None:
        """Bring the TUN interface up."""
        logger.info("Bringing up TUN interface '%s'", self.name)
        self._exec(["ip", "link", "set", "dev", self.name, "up"])

    def down(self) -> None:
        """Bring the TUN interface down."""
        logger.info("Bringing down TUN interface '%s'", self.name)
        self._exec(["ip", "link", "set", "dev", self.name, "down"], check=False)

    def read(self, size: int = 2048) -> bytes:
        """
        Read an incoming raw IP packet from the TUN interface.

        Args:
            size: Buffer read size in bytes.

        Returns:
            Raw IP packet bytes.
        """
        if not self.is_open or self.fd is None:
            raise OSError("TUN interface is not open")
        return os.read(self.fd, size)

    def write(self, packet: bytes) -> int:
        """
        Inject a raw IP packet into the virtual network stack via TUN interface.

        Args:
            packet: Raw IP packet bytes.

        Returns:
            Number of bytes written.
        """
        if not self.is_open or self.fd is None:
            raise OSError("TUN interface is not open")
        return os.write(self.fd, packet)

    def fileno(self) -> int:
        """Return the underlying file descriptor for event loops."""
        if not self.is_open or self.fd is None:
            raise OSError("TUN interface is not open")
        return self.fd

    def close(self) -> None:
        """Close the TUN device descriptor and cleanup."""
        if self.is_open and self.fd is not None:
            try:
                self.down()
            except Exception:
                pass
            try:
                os.close(self.fd)
                logger.info("Closed TUN interface '%s' (fd=%d)", self.name, self.fd)
            except Exception as e:
                logger.warning("Error closing TUN fd: %s", e)
            finally:
                self.fd = None
                self.is_open = False

    def _exec(self, cmd: list, check: bool = True) -> str:
        """Helper to run system networking commands."""
        cmd_str = " ".join(cmd)
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=check)
            return res.stdout.strip()
        except subprocess.CalledProcessError as e:
            logger.error("Failed executing '%s': %s", cmd_str, e.stderr.strip())
            if check:
                raise
            return ""

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
