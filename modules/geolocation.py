"""
geolocation.py
---------------
Basic, free-tier IP geolocation lookup via ip-api.com (no API key
required, generous rate limit for light recon use). If the target IP
can't be resolved or the lookup fails, returns a clear "unavailable"
payload rather than raising past the safe_run boundary unnecessarily.
"""

import requests


def get_geolocation(ip_address: str, timeout: float = 6.0) -> dict:
    if not ip_address:
        return {"available": False, "reason": "No IP address to geolocate"}

    url = f"http://ip-api.com/json/{ip_address}"
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    payload = response.json()

    if payload.get("status") != "success":
        return {"available": False, "reason": payload.get("message", "lookup failed")}

    return {
        "available": True,
        "ip": payload.get("query"),
        "country": payload.get("country"),
        "region": payload.get("regionName"),
        "city": payload.get("city"),
        "isp": payload.get("isp"),
        "org": payload.get("org"),
        "as": payload.get("as"),
        "lat": payload.get("lat"),
        "lon": payload.get("lon"),
    }
