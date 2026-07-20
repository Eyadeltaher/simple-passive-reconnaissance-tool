"""
report_generator.py
--------------------
Turns the raw results dict assembled by main.py into a polished,
client-ready reconnaissance report. Two output formats are supported:
Markdown (always) and a self-contained HTML file (styled, no external
dependencies) for easier sharing/printing to PDF.
"""

from datetime import datetime


def _fmt(value, fallback="Not available"):
    if value in (None, "", [], {}):
        return fallback
    return value


def _module_status_line(result: dict) -> str:
    if result is None:
        return "_Module did not run._"
    if result["status"] == "error":
        return f"_Data unavailable -- {result['error']}_"
    return ""


# ---------------------------------------------------------------------------
# MARKDOWN REPORT
# ---------------------------------------------------------------------------

def generate_markdown_report(results: dict) -> str:
    target = results["target"]
    lines = []

    lines.append(f"# Reconnaissance Report: {target['domain']}")
    lines.append("")
    lines.append(f"**Prepared:** {results['timestamp']}  ")
    lines.append(f"**Target:** {target['url']}  ")
    lines.append("**Scope:** Passive / publicly available information only.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(_build_executive_summary(results))
    lines.append("")
    lines.append("---")
    lines.append("")

    lines += _section_whois(results.get("whois"))
    lines += _section_dns(results.get("dns"), results.get("geolocation"))
    lines += _section_http(results.get("http_headers"))
    lines += _section_ssl(results.get("ssl"))
    lines += _section_robots_sitemap(results.get("robots"), results.get("sitemap"))
    lines += _section_security(results.get("security_analysis"), results.get("http_headers"))

    lines.append("---")
    lines.append("")
    lines.append("## Disclaimer")
    lines.append("")
    lines.append(
        "This report was generated automatically using the Web Recon Automation "
        "Framework and reflects publicly available information at the time of "
        "collection. It is intended as a starting point for authorized security "
        "assessment work, not a complete vulnerability assessment or penetration "
        "test. All testing beyond passive information gathering requires explicit "
        "written authorization from the target's owner."
    )
    lines.append("")

    return "\n".join(lines)


def _build_executive_summary(results: dict) -> str:
    target = results["target"]
    dns_result = results.get("dns")
    ssl_result = results.get("ssl")
    sec_result = results.get("security_analysis")

    points = []

    if dns_result and dns_result["status"] == "ok":
        a_records = dns_result["data"].get("A")
        if a_records:
            points.append(f"Resolves to {len(a_records)} IPv4 address(es).")
        elif a_records is None:
            points.append("**Domain does not appear to resolve (NXDOMAIN).**")

    if ssl_result and ssl_result["status"] == "ok":
        ssl_data = ssl_result["data"]
        if ssl_data["is_expired"]:
            points.append("**TLS certificate is EXPIRED.**")
        elif ssl_data["expiring_soon"]:
            points.append(f"TLS certificate expires soon ({ssl_data['days_remaining']} days remaining).")
        else:
            points.append(f"TLS certificate valid, {ssl_data['days_remaining']} days remaining.")
    elif ssl_result and ssl_result["status"] == "error":
        points.append("Could not establish a TLS connection on port 443.")

    if sec_result and sec_result["status"] == "ok":
        score = sec_result["data"]["security_header_score_pct"]
        missing_count = len(sec_result["data"]["missing_headers"])
        points.append(f"Security header coverage: {score}% ({missing_count} recommended header(s) missing).")

    if not points:
        points.append("Limited data could be collected for this target; see individual sections below.")

    return "\n".join(f"- {p}" for p in points)


def _section_whois(result) -> list:
    lines = ["## 1. WHOIS Information", ""]
    if result and result["status"] == "ok":
        d = result["data"]
        lines.append(f"| Field | Value |")
        lines.append(f"|---|---|")
        lines.append(f"| Registrar | {_fmt(d.get('registrar'))} |")
        lines.append(f"| Domain Name | {_fmt(d.get('domain_name'))} |")
        lines.append(f"| Creation Date | {_fmt(d.get('creation_date'))} |")
        lines.append(f"| Expiration Date | {_fmt(d.get('expiration_date'))} |")
        lines.append(f"| Updated Date | {_fmt(d.get('updated_date'))} |")
        lines.append(f"| Organization | {_fmt(d.get('org'))} |")
        lines.append(f"| Country | {_fmt(d.get('country'))} |")
        lines.append(f"| Status | {_fmt(', '.join(d.get('status', [])) if d.get('status') else None)} |")
        ns = d.get("name_servers") or []
        lines.append(f"| Name Servers | {_fmt(', '.join(ns) if ns else None)} |")
    else:
        lines.append(_module_status_line(result))
    lines.append("")
    return lines


def _section_dns(dns_result, geo_result) -> list:
    lines = ["## 2. DNS Records & IP Geolocation", ""]
    if dns_result and dns_result["status"] == "ok":
        d = dns_result["data"]
        lines.append("| Record Type | Value(s) |")
        lines.append("|---|---|")
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
            val = d.get(rtype)
            if val is None:
                display = "NXDOMAIN"
            elif val == "timeout":
                display = "Lookup timed out"
            elif not val:
                display = "None found"
            else:
                display = "<br>".join(val)
            lines.append(f"| {rtype} | {display} |")
        lines.append("")
    else:
        lines.append(_module_status_line(dns_result))
        lines.append("")

    lines.append("### Geolocation")
    lines.append("")
    if geo_result and geo_result["status"] == "ok" and geo_result["data"].get("available"):
        g = geo_result["data"]
        lines.append(f"- **IP:** {g['ip']}")
        lines.append(f"- **Location:** {_fmt(g.get('city'))}, {_fmt(g.get('region'))}, {_fmt(g.get('country'))}")
        lines.append(f"- **ISP / Org:** {_fmt(g.get('isp'))} / {_fmt(g.get('org'))}")
        lines.append(f"- **AS:** {_fmt(g.get('as'))}")
    else:
        reason = geo_result["data"].get("reason") if geo_result and geo_result.get("data") else "unavailable"
        lines.append(f"_Geolocation unavailable -- {reason}_")
    lines.append("")
    return lines


def _section_http(result) -> list:
    lines = ["## 3. HTTP Response Headers", ""]
    if result and result["status"] == "ok":
        d = result["data"]
        lines.append(f"- **Final URL:** {d['final_url']}")
        lines.append(f"- **Status Code:** {d['status_code']}")
        if d["redirect_chain"]:
            lines.append(f"- **Redirect Chain:** {' -> '.join(d['redirect_chain'])}")
        lines.append("")
        lines.append("| Header | Value |")
        lines.append("|---|---|")
        for k, v in sorted(d["headers"].items()):
            v_display = str(v).replace("|", "\\|")
            lines.append(f"| {k} | {v_display} |")
    else:
        lines.append(_module_status_line(result))
    lines.append("")
    return lines


def _section_ssl(result) -> list:
    lines = ["## 4. SSL/TLS Certificate", ""]
    if result and result["status"] == "ok":
        d = result["data"]
        lines.append("| Field | Value |")
        lines.append("|---|---|")
        lines.append(f"| Subject (CN) | {_fmt(d['subject'].get('commonName'))} |")
        lines.append(f"| Issuer | {_fmt(d['issuer'].get('organizationName') or d['issuer'].get('commonName'))} |")
        lines.append(f"| Valid From | {d['valid_from']} |")
        lines.append(f"| Valid Until | {d['valid_until']} |")
        lines.append(f"| Days Remaining | {d['days_remaining']} |")
        lines.append(f"| TLS Version | {_fmt(d['tls_version'])} |")
        lines.append(f"| Cipher Suite | {_fmt(d['cipher_suite'])} |")
        sans = d.get("subject_alt_names") or []
        lines.append(f"| Subject Alt. Names | {_fmt(', '.join(sans) if sans else None)} |")
        if d["is_expired"]:
            lines.append("")
            lines.append("> **Finding:** Certificate is expired. Visitors will see browser security warnings.")
        elif d["expiring_soon"]:
            lines.append("")
            lines.append(f"> **Finding:** Certificate expires within 30 days ({d['days_remaining']} days left).")
    else:
        lines.append(_module_status_line(result))
    lines.append("")
    return lines


def _section_robots_sitemap(robots_result, sitemap_result) -> list:
    lines = ["## 5. robots.txt & sitemap.xml", ""]

    lines.append("### robots.txt")
    if robots_result and robots_result["status"] == "ok":
        d = robots_result["data"]
        if d["found"]:
            lines.append(f"- **Found at:** {d['url']}")
            if d["disallowed_paths"]:
                lines.append(f"- **Disallowed paths ({len(d['disallowed_paths'])}):**")
                for p in d["disallowed_paths"][:25]:
                    lines.append(f"  - `{p}`")
                if len(d["disallowed_paths"]) > 25:
                    lines.append(f"  - _...and {len(d['disallowed_paths']) - 25} more_")
            else:
                lines.append("- No Disallow directives found.")
            if d["sitemaps"]:
                lines.append(f"- **Sitemaps declared:** {', '.join(d['sitemaps'])}")
        else:
            lines.append("- Not found.")
    else:
        lines.append(_module_status_line(robots_result))
    lines.append("")

    lines.append("### sitemap.xml")
    if sitemap_result and sitemap_result["status"] == "ok":
        d = sitemap_result["data"]
        if d["found"]:
            lines.append(f"- **Found at:** {d['url']}")
            lines.append(f"- **Estimated URL entries:** {d['url_count_estimate']}")
        else:
            lines.append("- Not found.")
    else:
        lines.append(_module_status_line(sitemap_result))
    lines.append("")
    return lines


def _section_security(sec_result, http_result) -> list:
    lines = ["## 6. Security Observations", ""]
    if sec_result and sec_result["status"] == "ok":
        d = sec_result["data"]
        lines.append(f"**Security header coverage score: {d['security_header_score_pct']}%**")
        lines.append("")
        if d["present_headers"]:
            lines.append("**Present:**")
            for h in d["present_headers"]:
                lines.append(f"- {h}")
            lines.append("")
        if d["missing_headers"]:
            lines.append("**Missing / Recommended:**")
            lines.append("")
            lines.append("| Header | Why it matters |")
            lines.append("|---|---|")
            for item in d["missing_headers"]:
                lines.append(f"| {item['header']} | {item['risk']} |")
            lines.append("")
        if d["banner_exposure"]:
            lines.append("**Banner exposure:**")
            for item in d["banner_exposure"]:
                lines.append(f"- `{item['header']}: {item['value']}` -- {item['note']}")
            lines.append("")
        if d["cookie_notes"]:
            lines.append("**Cookie configuration notes:**")
            for note in d["cookie_notes"]:
                lines.append(f"- {note}")
            lines.append("")
    else:
        lines.append(_module_status_line(sec_result))
        lines.append("")
    return lines


# ---------------------------------------------------------------------------
# HTML REPORT
# ---------------------------------------------------------------------------

_HTML_CSS = """
body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
       max-width: 900px; margin: 40px auto; padding: 0 20px; color: #1a1a1a; line-height: 1.55; }
h1 { border-bottom: 3px solid #1a1a1a; padding-bottom: 10px; }
h2 { margin-top: 40px; border-bottom: 1px solid #ccc; padding-bottom: 6px; }
h3 { margin-top: 24px; }
table { border-collapse: collapse; width: 100%; margin: 12px 0; font-size: 14px; }
th, td { border: 1px solid #ddd; padding: 8px 10px; text-align: left; vertical-align: top; }
th { background: #1a1a1a; color: #fff; }
tr:nth-child(even) { background: #f7f7f7; }
code { background: #f0f0f0; padding: 2px 5px; border-radius: 3px; font-size: 13px; }
blockquote { border-left: 4px solid #d97706; background: #fffbeb; margin: 12px 0; padding: 8px 16px; }
.meta { color: #555; font-size: 14px; }
.disclaimer { font-size: 13px; color: #666; margin-top: 40px; border-top: 1px solid #ccc; padding-top: 16px; }
ul { margin-top: 6px; }
"""


def generate_html_report(markdown_text: str, title: str) -> str:
    """
    Lightweight Markdown -> HTML conversion covering just the constructs
    this report actually uses (headings, tables, bold, bullet lists,
    blockquotes, inline code, hr). Avoids pulling in an external
    Markdown dependency for a self-contained, professional deliverable.
    """
    import re

    html_lines = []
    in_table = False
    in_list = False

    for raw_line in markdown_text.split("\n"):
        line = raw_line.rstrip()

        if line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if all(set(c) <= {"-", " "} for c in cells):
                continue  # header separator row
            if not in_table:
                html_lines.append("<table>")
                in_table = True
                tag = "th"
            else:
                tag = "td"
            row = "".join(f"<{tag}>{_inline(c)}</{tag}>" for c in cells)
            html_lines.append(f"<tr>{row}</tr>")
            continue
        elif in_table:
            html_lines.append("</table>")
            in_table = False

        if line.startswith("- "):
            if not in_list:
                html_lines.append("<ul>")
                in_list = True
            html_lines.append(f"<li>{_inline(line[2:])}</li>")
            continue
        elif in_list and not line.startswith("  -"):
            html_lines.append("</ul>")
            in_list = False

        if line.startswith("# "):
            html_lines.append(f"<h1>{_inline(line[2:])}</h1>")
        elif line.startswith("## "):
            html_lines.append(f"<h2>{_inline(line[3:])}</h2>")
        elif line.startswith("### "):
            html_lines.append(f"<h3>{_inline(line[4:])}</h3>")
        elif line.startswith("> "):
            html_lines.append(f"<blockquote>{_inline(line[2:])}</blockquote>")
        elif line.strip() == "---":
            html_lines.append("<hr>")
        elif line.strip() == "":
            html_lines.append("")
        else:
            html_lines.append(f"<p>{_inline(line)}</p>")

    if in_table:
        html_lines.append("</table>")
    if in_list:
        html_lines.append("</ul>")

    body = "\n".join(html_lines)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>{_HTML_CSS}</style>
</head>
<body>
{body}
</body>
</html>"""


def _inline(text: str) -> str:
    """Handle inline markdown: bold, inline code, br."""
    import re

    text = text.replace("<br>", "<br>")  # already literal HTML, keep as-is
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"`(.+?)`", r"<code>\1</code>", text)
    return text


def save_reports(results: dict, output_dir: str) -> dict:
    """Writes both .md and .html reports to output_dir, returns their paths."""
    import os

    os.makedirs(output_dir, exist_ok=True)
    domain = results["target"]["domain"]
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"recon_report_{domain}_{stamp}"

    md_content = generate_markdown_report(results)
    md_path = os.path.join(output_dir, f"{base_name}.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    html_content = generate_html_report(md_content, title=f"Recon Report - {domain}")
    html_path = os.path.join(output_dir, f"{base_name}.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return {"markdown": md_path, "html": html_path}
