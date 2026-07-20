"""
dns_lookup.py
-------------
Resolves the common DNS record types for the target: A, AAAA, MX, NS,
TXT, CNAME. Each record type is resolved independently so a missing
record type (e.g. no AAAA) doesn't block the others.
"""

import dns.resolver

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]


def get_dns_records(domain: str, timeout: float = 5.0) -> dict:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    results = {}
    for record_type in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, record_type)
            results[record_type] = sorted(str(r).strip() for r in answers)
        except dns.resolver.NoAnswer:
            results[record_type] = []
        except dns.resolver.NXDOMAIN:
            results[record_type] = None  # domain does not exist at all
        except dns.exception.Timeout:
            results[record_type] = "timeout"
        except Exception:
            results[record_type] = []

    return results


def resolve_ip(domain: str) -> str:
    """Convenience helper: returns the first resolvable A record IP, or None."""
    try:
        answers = dns.resolver.resolve(domain, "A")
        return str(answers[0])
    except Exception:
        return None
