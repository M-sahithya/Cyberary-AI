"""
Target Allowlist (Stub — Phase 2)
Restricts offensive actions to explicitly registered lab targets.
Blocks arbitrary internet targets and public IP ranges.
"""

import ipaddress
from typing import Tuple

from app.config.settings import settings

# Default allowlisted lab targets (expanded in Phase 2 via database)
LAB_TARGETS = {
    "lab-server-01": {
        "ip": "10.0.1.10",
        "hostname": "lab-server-01.cyberary.local",
        "type": "linux",
        "authorized": True,
    },
    "lab-server-02": {
        "ip": "10.0.1.11",
        "hostname": "lab-server-02.cyberary.local",
        "type": "linux",
        "authorized": True,
    },
    "lab-honeypot-01": {
        "ip": "10.0.1.20",
        "hostname": "lab-honeypot-01.cyberary.local",
        "type": "honeypot",
        "authorized": True,
    },
    "lab-ubuntu-01": {
        "ip": "192.168.56.103",
        "hostname": "ubuntu-lab.local",
        "type": "linux",
        "authorized": True,
    },
}

# Private IP ranges considered safe for lab use
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is in a private range."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_RANGES)
    except ValueError:
        return False


def _extract_host(target: str) -> str:
    """Extract host/IP without protocol or port."""
    cleaned = target.strip()
    if "://" in cleaned:
        cleaned = cleaned.split("://", 1)[1]
    if "/" in cleaned:
        cleaned = cleaned.split("/", 1)[0]
    if ":" in cleaned:
        cleaned = cleaned.split(":", 1)[0]
    return cleaned


def validate_target(target: str) -> Tuple[bool, str]:
    """
    Validate that a target is authorized for offensive operations.

    Args:
        target: IP address, hostname, or URL to validate

    Returns:
        Tuple of (is_authorized, reason)
    """
    if not settings.LAB_MODE:
        return False, "LAB_MODE is disabled. All offensive operations are blocked."

    host = _extract_host(target)

    # Check if target or extracted host is in the allowlist
    for lookup in (target, host):
        if lookup in LAB_TARGETS:
            entry = LAB_TARGETS[lookup]
            if entry.get("authorized"):
                return True, f"Target '{target}' is authorized in the lab allowlist."
            else:
                return False, f"Target '{target}' exists but is not currently authorized."

    # Check if it matches a known lab hostname or IP
    for name, entry in LAB_TARGETS.items():
        if entry.get("hostname") in (target, host) or entry.get("ip") in (target, host):
            if entry.get("authorized"):
                return True, f"Target '{target}' matches authorized lab asset '{name}'."
            else:
                return False, f"Target '{target}' matches lab asset '{name}' but is not authorized."

    # In controlled lab mode, allow private lab subnet ranges
    if is_private_ip(host):
        return True, f"Target '{target}' is a verified private lab network asset."

    # Block all other targets
    return False, (
        f"Target '{target}' is NOT authorized. "
        "Offensive operations are restricted to registered lab targets only. "
        "Public/internet targets are blocked."
    )

