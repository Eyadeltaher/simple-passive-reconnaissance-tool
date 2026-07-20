# Web Recon Automation Framework

A modular, passive reconnaissance tool: point it at a domain, get back a
clean, client-ready report — WHOIS, DNS, HTTP headers, TLS certificate,
robots.txt/sitemap.xml, and a security-header audit — without touching
twenty separate tools by hand.

## Features

- **WHOIS** — registrar, creation/expiry dates, name servers
- **DNS** — A, AAAA, MX, NS, TXT, CNAME records
- **IP Geolocation** — country/city/ISP for the resolved IP (via ip-api.com)
- **HTTP headers** — full response header dump, status code, redirect chain
- **TLS certificate** — issuer, subject, validity window, days-to-expiry, cipher
- **robots.txt** — full content, parsed Disallow paths, declared sitemaps
- **sitemap.xml** — presence check and estimated URL count
- **Security header audit** — CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy, Permissions-Policy, server-banner exposure, cookie flag checks
- **Fails gracefully** — a dead domain, timeout, or blocked module never
  crashes the run; it's logged and the report notes the gap
- **Reports** — both a Markdown file and a self-contained, styled HTML file

## Project structure

```
simple-passive-reconnaissance-tool/
├── main.py                     # CLI entry point / orchestrator
├── requirements.txt
├── modules/
│   ├── utils.py                 # logging, target normalization, safe_run wrapper
│   ├── whois_lookup.py
│   ├── dns_lookup.py
│   ├── geolocation.py
│   ├── http_headers.py
│   ├── ssl_cert.py
│   ├── robots_sitemap.py
│   └── security_analysis.py     # pure analysis layer over http_headers output
└── report/
    └── report_generator.py      # Markdown + HTML report builder
```

Each module has exactly one job and takes plain data in, returns plain
data out — no module depends on another module's internal state, only
on `main.py` passing along already-collected values (e.g. the resolved
IP goes from `dns_lookup` into `geolocation`).

## Installation

```bash
cd simple-passive-reconnaissance-tool
pip install -r requirements.txt
```

## Usage

```bash
# Domain or full URL both work
python main.py example.com
python main.py https://example.com

# Custom output directory, verbose logging, custom timeout
python main.py example.com --output ./reports --verbose --timeout 10

# No target given -> interactive prompt
python main.py
```

Reports are written to `./output/` by default as:
`recon_report_<domain>_<timestamp>.md` and `.html`.

## How failures are handled

Every collection module is wrapped by `safe_run()` in `modules/utils.py`.
If a module throws (timeout, connection refused, NXDOMAIN, blocked by a
firewall, whatever), the exception is caught, logged as a warning, and
the module's report section prints `_Data unavailable -- <reason>_`
instead of blank space or a stack trace. The scan always finishes and a
report always gets written.

## Extending it

To add a new recon module:
1. Write a plain function in `modules/your_module.py` that takes simple
   inputs and returns a dict (raise on failure, don't catch internally).
2. Wire it into `run_recon()` in `main.py` using the same
   `safe_run("Module label", logger)(your_function)(...)` pattern.
3. Add a `_section_your_module()` function in `report/report_generator.py`
   and call it from `generate_markdown_report()`.

## Legal / ethical note

This tool only collects information that is already public (WHOIS,
DNS, published HTTP responses, robots.txt, TLS certs presented to any
client). It does not scan ports, brute-force paths, or send anything
beyond a handful of ordinary GET requests. Even so, only point it at
targets you own or are explicitly authorized to assess.
