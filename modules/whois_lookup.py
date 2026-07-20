"""
whois_lookup.py
----------------
Pulls WHOIS registration data for the target domain: registrar,
creation/expiry dates, and name servers.
"""

import whois


def get_whois_info(domain: str) -> dict:
    """
    Returns a normalized dict of WHOIS fields. Raises on failure so the
    safe_run wrapper in main.py can catch and log it uniformly.
    """
    record = whois.whois(domain)

    def _first(value):
        """WHOIS libraries sometimes return a list for date/registrar fields."""
        if isinstance(value, list):
            return value[0] if value else None
        return value

    return {
        "domain_name": _first(record.domain_name) or domain,
        "registrar": _first(record.registrar),
        "creation_date": str(_first(record.creation_date)) if record.creation_date else None,
        "expiration_date": str(_first(record.expiration_date)) if record.expiration_date else None,
        "updated_date": str(_first(record.updated_date)) if record.updated_date else None,
        "name_servers": sorted(set(record.name_servers)) if record.name_servers else [],
        "status": record.status if isinstance(record.status, list) else ([record.status] if record.status else []),
        "emails": record.emails if isinstance(record.emails, list) else ([record.emails] if record.emails else []),
        "org": _first(getattr(record, "org", None)),
        "country": _first(getattr(record, "country", None)),
    }
