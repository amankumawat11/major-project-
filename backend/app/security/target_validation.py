import ipaddress
import re
import socket
from urllib.parse import urlparse
from typing import Tuple, Optional

# Disallowed private and special CIDR ranges for SSRF prevention
BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918 Private
    ipaddress.ip_network("100.64.0.0/10"),      # Shared Address Space
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link Local / Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 Private
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("192.88.99.0/24"),     # 6to4 Relay Anycast
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 Private
    ipaddress.ip_network("198.18.0.0/15"),      # Network Interconnect Device Benchmark
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved for future use
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6 blocked ranges
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("fc00::/7"),           # Unique Local Address (ULA)
    ipaddress.ip_network("fe80::/10"),          # Link-local
    ipaddress.ip_network("ff00::/8"),           # Multicast
]

DISALLOWED_HOSTNAMES = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "metadata.google.internal",
    "instance-data",
}

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)

def is_ip_blocked(ip_str: str) -> bool:
    """Check if an IP address belongs to any private, loopback, or reserved range."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved:
            return True
        for network in BLOCKED_IP_NETWORKS:
            if ip_obj in network:
                return True
        return False
    except ValueError:
        return True

def normalize_target(raw_target: str) -> Tuple[str, str]:
    """
    Normalizes a user-supplied target (e.g. 'example.com', 'https://example.com/test')
    Returns: (normalized_url, domain)
    Raises: ValueError on invalid input or dangerous schemes
    """
    target = raw_target.strip().lower()
    if not target:
        raise ValueError("Target cannot be empty.")

    # Check for scheme
    if "://" not in target:
        # Default to https
        url = f"https://{target}"
    else:
        url = target

    parsed = urlparse(url)
    
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported protocol scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted.")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid target: unable to extract a valid domain or host name.")

    # Strip trailing dot if present
    hostname = hostname.rstrip(".")

    # Reject disallowed hostnames
    if hostname in DISALLOWED_HOSTNAMES or hostname.endswith(".localhost") or hostname.endswith(".local") or hostname.endswith(".internal"):
        raise ValueError(f"Scanning internal or loopback hostname '{hostname}' is strictly prohibited.")

    return url, hostname

def validate_target_security(raw_target: str) -> dict:
    """
    Comprehensive validation for SSRF protection and DNS verification.
    Resolves domain to IP and ensures it is public.
    """
    normalized_url, domain = normalize_target(raw_target)

    # Check if domain is directly an IP
    is_direct_ip = False
    try:
        ip_obj = ipaddress.ip_address(domain)
        is_direct_ip = True
    except ValueError:
        is_direct_ip = False

    if is_direct_ip:
        # Direct IP entered
        if is_ip_blocked(str(ip_obj)):
            raise ValueError(f"Target IP '{domain}' is a private, loopback, or reserved address. Scanning is blocked for security.")
        resolved_ip = str(ip_obj)
    else:
        # It's a hostname, validate syntax
        if not DOMAIN_REGEX.match(domain):
            raise ValueError(f"Invalid domain format '{domain}'. Please provide a valid fully qualified domain name.")

        # Resolve DNS to get actual IP(s)
        try:
            addr_info = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            if not addr_info:
                raise ValueError(f"Domain '{domain}' could not be resolved by DNS.")
            
            # Verify every resolved IP to protect against DNS rebinding
            resolved_ip = None
            for item in addr_info:
                ip_addr = item[4][0]
                if is_ip_blocked(ip_addr):
                    raise ValueError(f"Domain '{domain}' resolves to a restricted/internal IP address ({ip_addr}). Scanning is blocked.")
                if not resolved_ip:
                    resolved_ip = ip_addr
        except socket.gaierror as e:
            raise ValueError(f"DNS resolution failed for '{domain}': Unable to find host.")

    return {
        "valid": True,
        "normalized_url": normalized_url,
        "domain": domain,
        "ip": resolved_ip
    }
