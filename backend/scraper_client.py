"""
Scraper Client — async wrapper around the credibility_checker scraper.

Runs the existing scraper in a thread pool with a configurable timeout.
Returns a normalized dict of extracted signals, or None if the scraper
fails or times out. The rest of the pipeline degrades gracefully either way.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, date
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Add credibility_checker to the import path
_SCRAPER_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "credibility_checker",
)
if _SCRAPER_DIR not in sys.path:
    sys.path.insert(0, _SCRAPER_DIR)

# Thread pool shared across requests (scraper is synchronous + blocking)
_executor = ThreadPoolExecutor(max_workers=2)


def _run_scraper_sync(url: str) -> dict[str, Any] | None:
    """Call the credibility_checker pipeline synchronously.

    Returns the raw report dict, or None on any failure.
    """
    try:
        from normalizer import normalize_URL, extract_domain
        from extractor.scraper import get_soup
        from extractor.wrapper import extract_full_website_report

        normalized = normalize_URL(url)
        scrape_result = get_soup(normalized)
        if not scrape_result or not scrape_result.get("success"):
            logger.warning("Scraper fetch failed for %s", url)
            return None

        report = extract_full_website_report(normalized, scrape_result)
        return report

    except Exception:
        logger.exception("Scraper sync execution failed for %s", url)
        return None


def normalize_scraper_report(raw: dict[str, Any] | None) -> dict[str, Any] | None:
    """Extract the fields the heuristic engine cares about from a raw scraper report.

    Returns a flat dict with keys the heuristic engine checks, or None.
    """
    if not raw:
        return None

    try:
        result: dict[str, Any] = {}

        # Domain creation date → age in days
        creation_info = raw.get("5_domain_creation", {})
        creation_str = creation_info.get("creation_date")
        if creation_str and creation_str not in ("Unknown / Redacted", "Unknown", None):
            try:
                creation_date = datetime.strptime(str(creation_str)[:10], "%Y-%m-%d").date()
                age_days = (date.today() - creation_date).days
                result["domain_age_days"] = age_days
                result["domain_creation_date"] = str(creation_str)[:10]
            except (ValueError, TypeError):
                pass

        # SSL certificate info
        ssl_info = raw.get("6_ssl_certificate", {})
        if ssl_info:
            result["has_ssl"] = ssl_info.get("has_ssl", False)
            result["ssl_valid"] = ssl_info.get("is_valid", False)
            result["ssl_issuer"] = ssl_info.get("issuer")
            result["ssl_days_remaining"] = ssl_info.get("days_remaining")

        # Safety evaluation
        safety = raw.get("10_safety_and_reputation", {})
        if safety:
            result["safety_status"] = safety.get("safety_status")
            result["safety_risk_score"] = safety.get("risk_score")
            result["threat_flags"] = safety.get("threat_flags", [])

        # Tranco rank
        traffic = raw.get("12_traffic_estimates", {})
        tranco = traffic.get("tranco", {})
        if tranco.get("available"):
            result["tranco_rank"] = tranco.get("rank")

        # Credibility score
        credibility = raw.get("overall_credibility_score", {})
        if credibility:
            result["credibility_score"] = credibility.get("overall_score")
            result["credibility_grade"] = credibility.get("grade")

        # Redirect chain (from the scrape_result embedded if available)
        # The wrapper doesn't directly expose this, but we check for it
        redirect_chain = raw.get("redirect_chain", [])
        if redirect_chain:
            result["redirect_chain"] = redirect_chain
            result["redirect_count"] = len(redirect_chain)

        return result if result else None

    except Exception:
        logger.exception("Failed to normalize scraper report")
        return None


async def get_scraper_report(url: str, timeout: float = 5.0) -> dict[str, Any] | None:
    """Run the scraper in a thread pool with a timeout.

    Args:
        url:     The URL to analyze.
        timeout: Max seconds to wait. Defaults to 5.

    Returns:
        Normalized dict of scraper signals, or None if scraper fails/times out.
    """
    try:
        loop = asyncio.get_event_loop()
        raw_report = await asyncio.wait_for(
            loop.run_in_executor(_executor, _run_scraper_sync, url),
            timeout=timeout,
        )
        normalized = normalize_scraper_report(raw_report)
        if normalized:
            logger.info("Scraper completed for %s — %d signals extracted", url, len(normalized))
        else:
            logger.warning("Scraper returned no usable data for %s", url)
        return normalized

    except asyncio.TimeoutError:
        logger.warning("Scraper timed out after %.1fs for %s", timeout, url)
        return None
    except Exception:
        logger.exception("Scraper async wrapper failed for %s", url)
        return None
