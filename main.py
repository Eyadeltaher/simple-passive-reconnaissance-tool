#!/usr/bin/env python3
"""
main.py
-------
Web Recon Automation Framework -- entry point.

Usage:
    python main.py example.com
    python main.py https://example.com --output ./output --verbose
    python main.py                       (prompts for target interactively)

Orchestrates every recon module, keeps the run alive even if individual
modules fail, and hands the collected data off to the report generator.
"""

import argparse
import sys
from datetime import datetime

from modules.utils import setup_logger, normalize_target, safe_run
from modules import (
    whois_lookup,
    dns_lookup,
    geolocation,
    http_headers,
    ssl_cert,
    robots_sitemap,
    security_analysis,
)
from report.report_generator import save_reports


def parse_args():
    parser = argparse.ArgumentParser(
        description="Web Recon Automation Framework -- passive OSINT recon report generator."
    )
    parser.add_argument("target", nargs="?", help="Target domain or URL (e.g. example.com)")
    parser.add_argument("-o", "--output", default="./output", help="Output directory for the report (default: ./output)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug logging")
    parser.add_argument("--timeout", type=float, default=8.0, help="Per-request network timeout in seconds (default: 8)")
    return parser.parse_args()


def run_recon(raw_target: str, timeout: float, logger) -> dict:
    target = normalize_target(raw_target)
    logger.info(f"Target normalized: {target['domain']} ({target['url']})")

    results = {
        "target": target,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    # --- WHOIS ---
    results["whois"] = safe_run("WHOIS lookup", logger)(whois_lookup.get_whois_info)(target["domain"])

    # --- DNS ---
    dns_result = safe_run("DNS record lookup", logger)(dns_lookup.get_dns_records)(target["domain"], timeout)
    results["dns"] = dns_result

    # --- Geolocation (depends on resolved IP) ---
    resolved_ip = None
    if dns_result["status"] == "ok" and dns_result["data"].get("A"):
        resolved_ip = dns_result["data"]["A"][0]
    results["geolocation"] = safe_run("IP geolocation", logger)(geolocation.get_geolocation)(resolved_ip, timeout)

    # --- HTTP headers ---
    http_result = safe_run("HTTP header collection", logger)(http_headers.get_http_headers)(target["url"], timeout)
    results["http_headers"] = http_result

    # --- SSL/TLS ---
    results["ssl"] = safe_run("SSL/TLS certificate inspection", logger)(ssl_cert.get_ssl_info)(target["hostname"], 443, timeout)

    # --- robots.txt ---
    robots_result = safe_run("robots.txt collection", logger)(robots_sitemap.get_robots_txt)(target["url"], timeout)
    results["robots"] = robots_result

    # --- sitemap.xml ---
    robots_sitemaps = []
    if robots_result["status"] == "ok" and robots_result["data"].get("found"):
        robots_sitemaps = robots_result["data"].get("sitemaps", [])
    results["sitemap"] = safe_run("sitemap.xml collection", logger)(robots_sitemap.get_sitemap_xml)(
        target["url"], robots_sitemaps, timeout
    )

    # --- Security header analysis (pure analysis, depends on http_headers) ---
    if http_result["status"] == "ok":
        results["security_analysis"] = safe_run("Security header analysis", logger)(
            security_analysis.analyze_security_headers
        )(http_result["data"]["headers"])
    else:
        results["security_analysis"] = {
            "status": "error",
            "module": "Security header analysis",
            "data": None,
            "error": "Skipped -- no HTTP headers were collected.",
        }

    return results


def main():
    args = parse_args()
    logger = setup_logger(verbose=args.verbose)

    raw_target = args.target or input("Enter target domain or URL: ").strip()
    if not raw_target:
        logger.error("No target provided. Exiting.")
        sys.exit(1)

    logger.info("=" * 60)
    logger.info("Web Recon Automation Framework -- starting scan")
    logger.info("=" * 60)

    results = run_recon(raw_target, args.timeout, logger)

    logger.info("Generating report...")
    paths = save_reports(results, args.output)

    logger.info("=" * 60)
    logger.info("Scan complete.")
    logger.info(f"Markdown report: {paths['markdown']}")
    logger.info(f"HTML report:     {paths['html']}")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
