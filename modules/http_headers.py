"""
http_headers.py
----------------
Fetches the target's HTTP response headers and basic response metadata
(status code, final URL after redirects, server banner). This is also
the data source that security_analysis.py inspects for missing headers.
"""

import requests

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; WebReconFramework/1.0; +recon-report)"
}


def get_http_headers(url: str, timeout: float = 8.0) -> dict:
    response = requests.get(
        url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True
    )
    return {
        "final_url": response.url,
        "status_code": response.status_code,
        "redirect_chain": [r.url for r in response.history],
        "headers": dict(response.headers),
        "server_banner": response.headers.get("Server"),
        "powered_by": response.headers.get("X-Powered-By"),
    }
