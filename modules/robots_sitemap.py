"""
robots_sitemap.py
------------------
Fetches robots.txt and sitemap.xml if they exist. Also extracts any
Sitemap: directives declared inside robots.txt, and pulls a preview of
disallowed paths -- these are frequently useful recon signals (they can
reveal admin panels, staging paths, etc. that the site owner didn't want
crawled but are still publicly requestable).
"""

import requests

from modules.http_headers import DEFAULT_HEADERS


def _fetch_text(url: str, timeout: float) -> tuple:
    try:
        resp = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout)
        if resp.status_code == 200 and resp.text.strip():
            return True, resp.text
        return False, None
    except requests.RequestException:
        return False, None


def get_robots_txt(base_url: str, timeout: float = 8.0) -> dict:
    url = base_url.rstrip("/") + "/robots.txt"
    found, content = _fetch_text(url, timeout)
    if not found:
        return {"found": False, "url": url, "content": None, "disallowed_paths": [], "sitemaps": []}

    disallowed = []
    sitemaps = []
    for line in content.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                disallowed.append(path)
        elif line.lower().startswith("sitemap:"):
            sitemaps.append(line.split(":", 1)[1].strip())

    return {
        "found": True,
        "url": url,
        "content": content[:3000],  # cap for report readability
        "disallowed_paths": disallowed[:50],
        "sitemaps": sitemaps,
    }


def get_sitemap_xml(base_url: str, robots_sitemaps: list, timeout: float = 8.0) -> dict:
    candidates = list(robots_sitemaps) if robots_sitemaps else []
    default_url = base_url.rstrip("/") + "/sitemap.xml"
    if default_url not in candidates:
        candidates.append(default_url)

    for url in candidates:
        found, content = _fetch_text(url, timeout)
        if found:
            url_count = content.count("<url>") + content.count("<url ")
            return {
                "found": True,
                "url": url,
                "url_count_estimate": url_count,
                "content_preview": content[:2000],
            }

    return {"found": False, "url": default_url, "url_count_estimate": 0, "content_preview": None}
