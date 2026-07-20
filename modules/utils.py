"""
utils.py
--------
Shared helpers used across every recon module: logging setup, target
normalization, and a safe-execution decorator so that a failure in any
single module (timeout, blocked request, dead domain) never crashes the
whole framework -- it just gets logged and the report notes the gap.
"""

import functools
import logging
import re
import sys
from urllib.parse import urlparse


def setup_logger(name: str = "webrecon", verbose: bool = False) -> logging.Logger:
    """Create a single shared logger with a clean console format."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger  # already configured, avoid duplicate handlers

    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(level)

    handler = logging.StreamHandler(sys.stdout)
    fmt = logging.Formatter("[%(levelname)s] %(name)s: %(message)s")
    handler.setFormatter(fmt)
    logger.addHandler(handler)
    return logger


def normalize_target(raw_target: str) -> dict:
    """
    Accepts messy user input ('example.com', 'https://example.com/path',
    'www.example.com') and returns a consistent dict with the pieces every
    module needs.
    """
    raw_target = raw_target.strip()
    if not re.match(r"^https?://", raw_target):
        url = f"https://{raw_target}"
    else:
        url = raw_target

    parsed = urlparse(url)
    hostname = parsed.hostname or raw_target
    domain = hostname.lower()
    if domain.startswith("www."):
        bare_domain = domain[4:]
    else:
        bare_domain = domain

    return {
        "raw_input": raw_target,
        "url": url,
        "hostname": hostname,
        "domain": bare_domain,
    }


def safe_run(module_name: str, logger: logging.Logger):
    """
    Decorator that wraps a recon module's entry function. On any exception
    it logs the failure and returns a standardized error payload instead
    of propagating the exception, so main.py never has to try/except each
    module individually.
    """

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                logger.info(f"Running {module_name}...")
                result = func(*args, **kwargs)
                logger.info(f"{module_name} completed.")
                return {"status": "ok", "module": module_name, "data": result}
            except Exception as exc:  # noqa: BLE001 - intentional catch-all boundary
                logger.warning(f"{module_name} failed: {exc}")
                return {
                    "status": "error",
                    "module": module_name,
                    "data": None,
                    "error": str(exc),
                }

        return wrapper

    return decorator
