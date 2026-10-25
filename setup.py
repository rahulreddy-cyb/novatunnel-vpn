import os
from setuptools import setup, find_packages

def read_requirements():
    req_file = os.path.join(os.path.dirname(__file__), "requirements.txt")
    if os.path.exists(req_file):
        with open(req_file, "r", encoding="utf-8") as f:
            return [
                line.strip()
                for line in f
                if line.strip() and not line.startswith("#")
            ]
    return [
        "cryptography>=41.0.0",
        "pyroute2>=0.7.0",
        "flask>=3.0.0",
        "click>=8.1.0",
        "tomli>=2.0.0",
        "tomli-w>=1.0.0",
        "qrcode>=7.4",
        "Pillow>=10.0.0",
        "bcrypt>=4.0.0",
    ]

setup(
    name="novatunnel-vpn",
    version="1.0.0",
    description="High-performance TUN-based VPN with ChaCha20-Poly1305 and X25519",
    author="NovaTunnel Team",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "dashboard": ["templates/*"],
    },
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "novatunnel-server=cli.novatunnel_server:main",
            "novatunnel-client=cli.novatunnel_client:main",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Topic :: System :: Networking",
        "Topic :: Security :: Cryptography",
    ],
    python_requires=">=3.10",
)
