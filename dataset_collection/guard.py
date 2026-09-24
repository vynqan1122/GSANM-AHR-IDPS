"""Target allowlist for lab-only traffic generation."""

from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse


DEFAULT_ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1", "nginx", "dvwa"}
PRIVATE_RANGES = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


class UnsafeTarget(ValueError):
    """The requested target is outside the explicit lab allowlist."""


def _explicit_hosts() -> set[str]:
    configured = os.getenv("AHR_TARGET_ALLOWLIST", "")
    return {item.strip().lower() for item in configured.split(",") if item.strip()}


def _ip_allowed(ip: ipaddress._BaseAddress) -> bool:
    if ip.is_loopback:
        return True
    return any(ip in network for network in PRIVATE_RANGES)


def assert_lab_target(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise UnsafeTarget("target must be an http(s) URL with a hostname")
    host = parsed.hostname.lower()
    allowed_hosts = DEFAULT_ALLOWED_HOSTS | _explicit_hosts()
    if host in allowed_hosts:
        return url.rstrip("/")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None and _ip_allowed(ip):
        return url.rstrip("/")
    if host.endswith(".local") and host in allowed_hosts:
        return url.rstrip("/")
    # Resolve only after literal/explicit checks; never treat a public DNS name
    # as safe just because one response happens to be private.
    if host not in allowed_hosts:
        raise UnsafeTarget(f"target host is not explicitly allowed: {host}")
    try:
        resolved = {ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(host, parsed.port or 80)}
    except OSError as exc:
        raise UnsafeTarget(f"target host cannot be resolved safely: {host}") from exc
    if not resolved or not all(_ip_allowed(item) for item in resolved):
        raise UnsafeTarget(f"target host resolves outside lab ranges: {host}")
    return url.rstrip("/")
