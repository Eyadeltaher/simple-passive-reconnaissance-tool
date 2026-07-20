"""
security_analysis.py
---------------------
Takes the HTTP headers already collected and evaluates them against a
checklist of security-relevant headers. This module does not make any
network requests itself -- it's a pure analysis layer on top of
http_headers.py output, which keeps it easy to unit test.
"""

SECURITY_HEADER_CHECKLIST = {
    "Content-Security-Policy": "Mitigates XSS and data-injection attacks by restricting allowed content sources.",
    "Strict-Transport-Security": "Forces browsers to use HTTPS only (HSTS), preventing downgrade/SSL-strip attacks.",
    "X-Frame-Options": "Prevents clickjacking by controlling whether the page can be framed.",
    "X-Content-Type-Options": "Prevents MIME-sniffing attacks (should be 'nosniff').",
    "Referrer-Policy": "Controls how much referrer information is leaked to other sites.",
    "Permissions-Policy": "Restricts which browser features/APIs the page may use.",
}


def analyze_security_headers(headers: dict) -> dict:
    """
    headers: the raw header dict from http_headers.get_http_headers()['headers']
    Returns present/missing headers plus a few extra banner-exposure notes.
    """
    # Header names can vary in case; normalize for lookup.
    lower_map = {k.lower(): (k, v) for k, v in (headers or {}).items()}

    present = {}
    missing = []
    for header_name, explanation in SECURITY_HEADER_CHECKLIST.items():
        key = header_name.lower()
        if key in lower_map:
            present[header_name] = lower_map[key][1]
        else:
            missing.append({"header": header_name, "risk": explanation})

    banner_exposure = []
    for banner_header in ("Server", "X-Powered-By"):
        key = banner_header.lower()
        if key in lower_map:
            banner_exposure.append(
                {"header": banner_header, "value": lower_map[key][1],
                 "note": "Reveals server/framework version info useful for attacker fingerprinting."}
            )

    cookie_notes = []
    if "set-cookie" in lower_map:
        cookie_value = lower_map["set-cookie"][1]
        for attr, note in (
            ("HttpOnly", "Cookie missing HttpOnly -- readable by JavaScript, raising XSS-theft risk."),
            ("Secure", "Cookie missing Secure -- may be sent over plain HTTP."),
            ("SameSite", "Cookie missing SameSite -- weaker CSRF protection."),
        ):
            if attr.lower() not in cookie_value.lower():
                cookie_notes.append(note)

    total_checked = len(SECURITY_HEADER_CHECKLIST)
    score = round((len(present) / total_checked) * 100) if total_checked else 0

    return {
        "present_headers": present,
        "missing_headers": missing,
        "banner_exposure": banner_exposure,
        "cookie_notes": cookie_notes,
        "security_header_score_pct": score,
    }
