"""
URL Heuristic Engine — rule-based checks for phishing/malicious URL indicators.

Returns a list of Finding objects with severity tiers (CRITICAL/HIGH/MEDIUM/LOW).
Does NOT call homoglyph detection itself — receives pre-computed homoglyph findings
and merges them with its own findings.

Scraper data is optional enrichment — the function degrades gracefully without it.
"""

from __future__ import annotations

import logging
import os
import re
import sys
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models import Finding, Severity

logger = logging.getLogger(__name__)

# ── Pre-compiled regex patterns ──────────────────────────────────────────
IP_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
ENCODED_CHARS_REGEX = re.compile(r"(%00|%2e|(%[0-9a-fA-F]{2}){4,})", re.IGNORECASE)

# ── Known brand names for keyword-in-domain detection ────────────────────
BRAND_KEYWORDS = {
    "paypal", "microsoft", "google", "apple", "amazon", "netflix", "chase",
    "wellsfargo", "bankofamerica", "citibank", "facebook", "instagram",
    "linkedin", "twitter", "dropbox", "adobe", "spotify", "coinbase",
    "binance", "metamask", "sbi", "hdfc", "icici", "paytm",
}

# Actual brand domains these keywords belong to (so we don't flag the real one)
BRAND_OFFICIAL_DOMAINS = {
    "paypal": ["paypal.com"], "microsoft": ["microsoft.com"], "google": ["google.com", "google.co.in", "google.co.uk"],
    "apple": ["apple.com", "apple.in"], "amazon": ["amazon.com", "amazon.in", "amazon.co.uk"], "netflix": ["netflix.com"],
    "chase": ["chase.com"], "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"], "citibank": ["citibank.com"],
    "facebook": ["facebook.com"], "instagram": ["instagram.com"],
    "linkedin": ["linkedin.com"], "twitter": ["twitter.com"], "dropbox": ["dropbox.com"],
    "adobe": ["adobe.com"], "spotify": ["spotify.com"], "coinbase": ["coinbase.com"],
    "binance": ["binance.com"], "metamask": ["metamask.io"],
    "sbi": ["sbi.co.in"], "hdfc": ["hdfcbank.com"], "icici": ["icicibank.com"],
    "paytm": ["paytm.com"],
}

# ── URL shortener domains ────────────────────────────────────────────────
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc",
    "rb.gy", "surl.li", "short.io",
}

# ── Suspicious TLDs ──────────────────────────────────────────────────────
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "xyz", "top", "club", "live", "icu",
    "space", "gq", "buzz", "work", "click", "link", "info", "support",
}


def run_url_heuristics(
    url: str,
    homoglyph_findings: list[Finding],
    scraper_data: dict | None = None,
) -> list[Finding]:
    """Run all URL heuristic checks and return a list of findings.

    Args:
        url:                 The URL to analyze.
        homoglyph_findings:  Pre-computed homoglyph/typosquat findings from homoglyph.py.
        scraper_data:        Optional normalized dict from scraper_client.py. Keys include:
                             domain_age_days, has_ssl, ssl_valid, safety_status,
                             tranco_rank, redirect_count, etc.

    Returns:
        Combined list of all triggered findings (including homoglyph findings).
    """
    findings: list[Finding] = []

    # Merge pre-computed homoglyph findings
    if homoglyph_findings:
        findings.extend(homoglyph_findings)

    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
    except Exception:
        return findings

    # ════════════════════════════════════════════════════════════════════
    # CRITICAL FINDINGS (score_delta +25 to +35, triggers floor at 85)
    # ════════════════════════════════════════════════════════════════════

    # 1. IP address instead of domain
    try:
        if IP_REGEX.match(hostname):
            findings.append(Finding(
                name="ip_as_domain",
                severity=Severity.CRITICAL,
                score_delta=30,
                reason=(
                    "URL uses a raw IP address instead of a domain name — "
                    "legitimate sites virtually never do this"
                ),
            ))
    except Exception:
        pass

    # 2. @ symbol in URL
    try:
        # Check the netloc portion for @, which indicates the URL has userinfo
        if "@" in (parsed.netloc or ""):
            findings.append(Finding(
                name="at_symbol",
                severity=Severity.CRITICAL,
                score_delta=35,
                reason=(
                    "URL contains @ symbol — browsers ignore everything before @, "
                    "making this a redirect trick (e.g., google.com@evil.com goes to evil.com)"
                ),
            ))
    except Exception:
        pass

    # 3. Punycode domain
    try:
        if hostname.startswith("xn--") or any(
            label.startswith("xn--") for label in hostname.split(".")
        ):
            findings.append(Finding(
                name="punycode_domain",
                severity=Severity.CRITICAL,
                score_delta=30,
                reason=(
                    "Domain uses Punycode encoding (xn-- prefix), which can render "
                    "Unicode lookalike characters as seemingly legitimate domain names"
                ),
            ))
    except Exception:
        pass

    # ════════════════════════════════════════════════════════════════════
    # HIGH FINDINGS (score_delta +15 to +20)
    # ════════════════════════════════════════════════════════════════════

    # 4 & 5. Domain age (from scraper's normalized output)
    if scraper_data:
        try:
            age_days = scraper_data.get("domain_age_days")
            if age_days is not None:
                if age_days < 7:
                    findings.append(Finding(
                        name="new_domain",
                        severity=Severity.HIGH,
                        score_delta=20,
                        reason=(
                            f"Domain registered only {age_days} day(s) ago — "
                            "phishing domains are typically brand new"
                        ),
                    ))
                elif age_days < 30:
                    findings.append(Finding(
                        name="young_domain",
                        severity=Severity.HIGH,
                        score_delta=15,
                        reason=(
                            f"Domain registered only {age_days} days ago — "
                            "recent registration is a risk indicator"
                        ),
                    ))
        except Exception:
            pass

    # 6. Known brand keyword in non-matching domain
    try:
        # Extract the base domain (SLD.TLD)
        parts = hostname.split(".")
        base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname

        for brand_kw in BRAND_KEYWORDS:
            if brand_kw in hostname:
                officials = BRAND_OFFICIAL_DOMAINS.get(brand_kw, [])
                is_official = False
                for official in officials:
                    if hostname == official or hostname.endswith("." + official):
                        is_official = True
                        break
                
                # Only flag if hostname is NOT any of the official domains
                if officials and not is_official:
                    findings.append(Finding(
                        name="brand_impersonation",
                        severity=Severity.CRITICAL,
                        score_delta=85,
                        reason=(
                            f'Domain contains brand name "{brand_kw}" but is not '
                            f"the official domain ({officials[0]})"
                        ),
                    ))
                    break  # One brand match is enough
    except Exception:
        pass

    # 7. Scraper safety status UNSAFE
    if scraper_data:
        try:
            status = scraper_data.get("safety_status", "")
            if status == "UNSAFE":
                findings.append(Finding(
                    name="scraper_unsafe",
                    severity=Severity.HIGH,
                    score_delta=20,
                    reason="Website safety evaluation returned UNSAFE status",
                ))
            elif status == "SUSPICIOUS":
                findings.append(Finding(
                    name="scraper_suspicious",
                    severity=Severity.MEDIUM,
                    score_delta=10,
                    reason="Website safety evaluation returned SUSPICIOUS status",
                ))
        except Exception:
            pass

    # ════════════════════════════════════════════════════════════════════
    # MEDIUM FINDINGS (score_delta +5 to +10)
    # ════════════════════════════════════════════════════════════════════

    # 8. URL shortener
    try:
        if any(hostname == s or hostname.endswith("." + s) for s in SHORTENERS):
            findings.append(Finding(
                name="url_shortener",
                severity=Severity.MEDIUM,
                score_delta=10,
                reason="URL uses a link shortener, hiding the true destination",
            ))
    except Exception:
        pass

    # 9. Suspicious TLD
    try:
        tld = parts[-1] if parts else ""
        if tld in SUSPICIOUS_TLDS:
            findings.append(Finding(
                name="suspicious_tld",
                severity=Severity.MEDIUM,
                score_delta=8,
                reason=f'TLD ".{tld}" is disproportionately abused for phishing',
            ))
    except Exception:
        pass

    # 10. Port number in URL
    try:
        port = parsed.port
        if port and port not in (80, 443):
            findings.append(Finding(
                name="unusual_port",
                severity=Severity.MEDIUM,
                score_delta=7,
                reason=(
                    f"URL specifies port {port} — unusual for legitimate consumer websites"
                ),
            ))
    except Exception:
        pass

    # 11. Encoded/obfuscated characters
    try:
        if ENCODED_CHARS_REGEX.search(url):
            findings.append(Finding(
                name="encoded_chars",
                severity=Severity.MEDIUM,
                score_delta=8,
                reason=(
                    "URL contains encoded/obfuscated characters that may be "
                    "designed to confuse parsers"
                ),
            ))
    except Exception:
        pass

    # 12. Excessive subdomains (>3 levels)
    try:
        labels = hostname.split(".")
        subdomain_count = max(0, len(labels) - 2)  # subtract SLD.TLD
        if subdomain_count > 3:
            findings.append(Finding(
                name="excessive_subdomains",
                severity=Severity.MEDIUM,
                score_delta=7,
                reason=(
                    f"URL has {subdomain_count} subdomain levels — "
                    "excessive stacking is a common phishing technique"
                ),
            ))
    except Exception:
        pass

    # 13. Redirect chain detected (from scraper)
    if scraper_data:
        try:
            redirect_count = scraper_data.get("redirect_count", 0)
            if redirect_count and redirect_count > 2:
                findings.append(Finding(
                    name="redirect_chain",
                    severity=Severity.MEDIUM,
                    score_delta=8,
                    reason=(
                        f"URL redirects {redirect_count} times before reaching "
                        "final destination"
                    ),
                ))
        except Exception:
            pass

    # ════════════════════════════════════════════════════════════════════
    # LOW FINDINGS (score_delta +1 to +5)
    # ════════════════════════════════════════════════════════════════════

    # 14. No HTTPS
    try:
        if parsed.scheme and parsed.scheme.lower() == "http":
            findings.append(Finding(
                name="no_https",
                severity=Severity.LOW,
                score_delta=5,
                reason="URL does not use HTTPS encryption",
            ))
    except Exception:
        pass

    # 15. Very long URL
    try:
        if len(url) > 100:
            findings.append(Finding(
                name="long_url",
                severity=Severity.LOW,
                score_delta=3,
                reason=f"Unusually long URL ({len(url)} characters)",
            ))
    except Exception:
        pass

    # 16. Many hyphens in domain
    try:
        hyphen_count = hostname.count("-")
        if hyphen_count >= 3:
            findings.append(Finding(
                name="many_hyphens",
                severity=Severity.LOW,
                score_delta=3,
                reason=(
                    f"Domain contains {hyphen_count} hyphens — "
                    "often used in phishing domains to impersonate brands"
                ),
            ))
    except Exception:
        pass

    return findings


def collect_safe_signals(url: str, scraper_data: dict | None) -> list[str]:
    """Collect positive trust indicators for the URL.

    These are shown when the risk score is low, to explain why something is safe.
    """
    signals: list[str] = []

    try:
        parsed = urlparse(url)
        if parsed.scheme == "https":
            signals.append("Uses HTTPS encrypted connection")
    except Exception:
        pass

    if scraper_data:
        try:
            if scraper_data.get("ssl_valid"):
                issuer = scraper_data.get("ssl_issuer", "")
                if issuer:
                    signals.append(f"Valid SSL certificate (issued by {issuer})")
                else:
                    signals.append("Valid SSL certificate")
        except Exception:
            pass

        try:
            age_days = scraper_data.get("domain_age_days")
            if age_days is not None and age_days > 365:
                years = age_days // 365
                signals.append(f"Domain registered {years} year(s) ago (established)")
        except Exception:
            pass

        try:
            rank = scraper_data.get("tranco_rank")
            if rank and rank < 100000:
                signals.append(f"Ranked #{rank:,} in Tranco top-sites list")
        except Exception:
            pass

        try:
            status = scraper_data.get("safety_status", "")
            if status == "SAFE":
                signals.append("Website safety evaluation returned SAFE status")
        except Exception:
            pass

        try:
            score = scraper_data.get("credibility_score")
            grade = scraper_data.get("credibility_grade", "")
            if score and score >= 80:
                signals.append(f"Credibility score: {score}/100 (grade {grade})")
        except Exception:
            pass

    # Signal for no typosquatting (added by the caller if homoglyph findings are empty)
    # — handled externally since we don't have access to homoglyph results here

    return signals
