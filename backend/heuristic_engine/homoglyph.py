"""
Homoglyph / Typosquat Detection Module

Detects lookalike domains by:
  1. Levenshtein edit distance against a reference list of ~300 brand domains
  2. Character substitution normalization (rn→m, vv→w, 0→o, etc.)
  3. Cyrillic homoglyph mapping
  4. Punycode decoding

All findings are CRITICAL severity (score_delta=30, triggers floor at 85).
"""

from __future__ import annotations

import json
import logging
import os
import sys
from urllib.parse import urlparse

import Levenshtein

# ── Import shared models ────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models import Finding, Severity

logger = logging.getLogger(__name__)

# ── Cyrillic → Latin mapping for homoglyph normalization ─────────────────
_CYRILLIC_MAP = {
    "\u0430": "a", "\u043e": "o", "\u0435": "e", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u0455": "s",
    "\u029c": "h", "\u0261": "g", "\u043d": "h", "\u043a": "k", "\u0442": "t",
    "\u0432": "b",
}

# ── Character substitution pairs ─────────────────────────────────────────
_SUBSTITUTION_PAIRS = [
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
    ("nn", "m"),
]

_CHAR_SWAPS = {
    "0": "o",
    "1": "l",
}


def load_brand_domains(json_path: str) -> list[dict]:
    """Load the brand domain reference list from a JSON file.

    Expected format: {"brands": [{"domain": "...", "name": "...", "email_domains": [...], "category": "..."}, ...]}
    Returns the list of brand dicts, or an empty list on failure.
    """
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        brands = data.get("brands", [])
        logger.info("Loaded %d brand domains from %s", len(brands), os.path.basename(json_path))
        return brands
    except Exception:
        logger.exception("Failed to load brand domains from %s", json_path)
        return []


def _extract_domain_from_url(url_or_domain: str) -> str:
    """Extract hostname from a URL or return the input if it's already a bare domain."""
    try:
        if "://" in url_or_domain:
            parsed = urlparse(url_or_domain)
            return (parsed.hostname or "").lower().strip()
        else:
            # Might be a bare domain like "rnicrosoft.com"
            return url_or_domain.lower().strip()
    except Exception:
        return url_or_domain.lower().strip()


def _get_base_domain(hostname: str) -> str:
    """Extract the registrable domain (SLD.TLD) from a hostname.

    Simplified approach — handles common cases like 'www.sub.example.com' → 'example.com'
    and 'sbi.co.in' → 'sbi.co.in' (two-part TLD).
    """
    parts = hostname.split(".")
    # Handle two-part TLDs (co.in, co.uk, com.au, etc.)
    two_part_tlds = {"co.in", "co.uk", "com.au", "co.nz", "com.br", "co.jp", "org.uk", "ac.in"}
    if len(parts) >= 3:
        possible_two_part = f"{parts[-2]}.{parts[-1]}"
        if possible_two_part in two_part_tlds:
            if len(parts) >= 3:
                return f"{parts[-3]}.{parts[-2]}.{parts[-1]}"
    if len(parts) >= 2:
        return f"{parts[-2]}.{parts[-1]}"
    return hostname


def _normalize_domain(domain: str) -> str:
    """Apply character substitution normalization to detect visual tricks.

    Applies Cyrillic→Latin mapping, then substitution pairs (rn→m, vv→w, etc.),
    then single-char swaps (0→o, 1→l).
    """
    norm = domain.lower()

    # Cyrillic homoglyphs first
    for cyrillic, latin in _CYRILLIC_MAP.items():
        norm = norm.replace(cyrillic, latin)

    # Multi-char substitution pairs
    for trick, real in _SUBSTITUTION_PAIRS:
        norm = norm.replace(trick, real)

    # Single-char swaps
    for trick_char, real_char in _CHAR_SWAPS.items():
        norm = norm.replace(trick_char, real_char)

    return norm


def _decode_punycode(domain: str) -> str:
    """Attempt to decode a punycode domain label."""
    try:
        parts = domain.split(".")
        decoded_parts = []
        for part in parts:
            if part.startswith("xn--"):
                decoded_parts.append(part.encode("ascii").decode("idna"))
            else:
                decoded_parts.append(part)
        return ".".join(decoded_parts)
    except Exception:
        return domain


def check_homoglyph(url_or_domain: str, brand_list: list[dict]) -> list[Finding]:
    """Check a URL or domain for typosquat / homoglyph matches against the brand list.

    Args:
        url_or_domain: A full URL (https://...) or bare domain string.
        brand_list:    The loaded brand domain reference list.

    Returns:
        A list of CRITICAL Finding objects for any matches found. Empty list if
        the domain is an exact match to a real brand (i.e., it IS the legitimate site).
    """
    try:
        findings: list[Finding] = []

        if not url_or_domain or not brand_list:
            return findings

        # Extract hostname from URL if needed
        hostname = _extract_domain_from_url(url_or_domain)
        if not hostname:
            return findings

        # If punycode, decode it
        if "xn--" in hostname:
            hostname = _decode_punycode(hostname)

        base_domain = _get_base_domain(hostname)

        # ── Step 1: Check exact match → it's the real domain, return empty ──
        brand_domain_set = set()
        for brand in brand_list:
            bd = brand.get("domain", "").lower()
            if bd:
                brand_domain_set.add(bd)

        if base_domain in brand_domain_set or hostname in brand_domain_set:
            return []  # It IS the real brand

        # ── Step 2: Normalized exact match (catches rn→m, Cyrillic, etc.) ──
        normalized_base = _normalize_domain(base_domain)
        normalized_host = _normalize_domain(hostname)

        for brand in brand_list:
            brand_domain = brand.get("domain", "").lower()
            if not brand_domain:
                continue

            # Check if normalized version matches a brand exactly
            if normalized_base == brand_domain or normalized_host == brand_domain:
                # Determine which substitution was used
                substitution_desc = _describe_substitution(base_domain, brand_domain)
                findings.append(Finding(
                    name="homoglyph_substitution",
                    severity=Severity.CRITICAL,
                    score_delta=30,
                    reason=(
                        f"Domain '{base_domain}' is a likely typosquat of "
                        f"'{brand_domain}'{substitution_desc}"
                    ),
                ))
                return findings  # One critical match is enough

        # ── Step 3: Levenshtein edit distance (catches typos and near-misses) ──
        for brand in brand_list:
            brand_domain = brand.get("domain", "").lower()
            if not brand_domain or len(brand_domain) <= 4:
                continue  # Skip very short domains to avoid false positives

            dist = Levenshtein.distance(base_domain, brand_domain)
            if 0 < dist <= 2:
                findings.append(Finding(
                    name="typosquat_edit_distance",
                    severity=Severity.CRITICAL,
                    score_delta=30,
                    reason=(
                        f"Domain '{base_domain}' is a likely typosquat of "
                        f"'{brand_domain}' (edit distance: {dist})"
                    ),
                ))
                return findings  # One critical match is enough

        return findings

    except Exception:
        logger.exception("Homoglyph check failed for %s", url_or_domain)
        return []


def check_email_domain_lookalike(
    sender_email: str, brand_list: list[dict]
) -> list[Finding]:
    """Check if a sender email's domain is a typosquat of a known brand email domain.

    Args:
        sender_email: The full email address (e.g., 'support@paypa1.com').
        brand_list:   The loaded brand domain reference list.

    Returns:
        A list of CRITICAL Finding objects for any matches found.
    """
    try:
        findings: list[Finding] = []

        if not sender_email or "@" not in sender_email:
            return findings

        _, domain = sender_email.rsplit("@", 1)
        domain = domain.lower().strip().rstrip(">")

        if not domain:
            return findings

        # Collect all legitimate email domains for exact-match exclusion
        all_legit_email_domains: set[str] = set()
        for brand in brand_list:
            for ed in brand.get("email_domains", []):
                all_legit_email_domains.add(ed.lower())
            bd = brand.get("domain", "").lower()
            if bd:
                all_legit_email_domains.add(bd)

        # Exact match → legitimate sender
        if domain in all_legit_email_domains:
            return []

        # Normalized check
        normalized = _normalize_domain(domain)
        for legit_domain in all_legit_email_domains:
            if normalized == legit_domain:
                findings.append(Finding(
                    name="email_domain_homoglyph",
                    severity=Severity.CRITICAL,
                    score_delta=30,
                    reason=(
                        f"Sender email domain '{domain}' is a likely typosquat of "
                        f"'{legit_domain}' (character substitution detected)"
                    ),
                ))
                return findings

        # Levenshtein distance
        for legit_domain in all_legit_email_domains:
            if len(legit_domain) <= 4:
                continue
            dist = Levenshtein.distance(domain, legit_domain)
            if 0 < dist <= 2:
                findings.append(Finding(
                    name="email_domain_typosquat",
                    severity=Severity.CRITICAL,
                    score_delta=30,
                    reason=(
                        f"Sender email domain '{domain}' is a likely typosquat of "
                        f"'{legit_domain}' (edit distance: {dist})"
                    ),
                ))
                return findings

        return findings

    except Exception:
        logger.exception("Email domain lookalike check failed for %s", sender_email)
        return []


def _describe_substitution(original: str, brand: str) -> str:
    """Generate a human-readable description of what substitution was likely used."""
    checks = [
        ("rn", "m", "rn→m"),
        ("vv", "w", "vv→w"),
        ("cl", "d", "cl→d"),
        ("nn", "m", "nn→m"),
    ]
    for trick, real, desc in checks:
        if trick in original and real in brand:
            return f" ({desc} substitution detected)"

    # Check single-char swaps
    if "0" in original:
        return " (0→o substitution detected)"
    if "1" in original:
        return " (1→l substitution detected)"

    # Check Cyrillic
    for c_char in _CYRILLIC_MAP:
        if c_char in original:
            return " (Cyrillic homoglyph characters detected)"

    return " (character substitution detected)"
