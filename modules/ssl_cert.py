"""
ssl_cert.py
-----------
Opens a raw TLS connection to the target on port 443 and reads the
presented certificate: issuer, subject, validity window, and days
remaining until expiry. Deliberately does not use requests here --
we want the actual handshake certificate, not a library abstraction.
"""

import socket
import ssl
from datetime import datetime, timezone


def _parse_name(name_tuples):
    """SSL certs store subject/issuer as a tuple of tuples of (key, value) pairs."""
    flat = {}
    for rdn in name_tuples:
        for key, value in rdn:
            flat[key] = value
    return flat


def get_ssl_info(hostname: str, port: int = 443, timeout: float = 8.0) -> dict:
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            cipher = ssock.cipher()

    not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=timezone.utc
    )
    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=timezone.utc
    )
    days_remaining = (not_after - datetime.now(timezone.utc)).days

    return {
        "subject": _parse_name(cert.get("subject", [])),
        "issuer": _parse_name(cert.get("issuer", [])),
        "valid_from": not_before.isoformat(),
        "valid_until": not_after.isoformat(),
        "days_remaining": days_remaining,
        "is_expired": days_remaining < 0,
        "expiring_soon": 0 <= days_remaining <= 30,
        "subject_alt_names": [v for k, v in cert.get("subjectAltName", []) if k == "DNS"],
        "tls_version": cipher[1] if cipher else None,
        "cipher_suite": cipher[0] if cipher else None,
    }
