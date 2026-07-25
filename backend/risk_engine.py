"""
Risk Engine — combines ML model output with heuristic findings into a final
risk score, classification, evidence list, and recommendation.

This is the ONLY module that knows about both the ML probability and the
heuristic findings. It enforces the critical-finding floor (≥85) and generates
both risk evidence and safe signals.
"""

from __future__ import annotations

import logging
from typing import Optional

from models import Finding, RiskResult, Severity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity sort order for evidence display
# ---------------------------------------------------------------------------
_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}

# ---------------------------------------------------------------------------
# Classification thresholds
# ---------------------------------------------------------------------------
_DANGEROUS_THRESHOLD = 65
_SUSPICIOUS_THRESHOLD = 30

# ---------------------------------------------------------------------------
# Critical-finding score floor
# ---------------------------------------------------------------------------
_CRITICAL_FLOOR = 85


def _clamp(value: float, lo: float = 0, hi: float = 100) -> int:
    """Clamp a numeric value to [lo, hi] and round to int."""
    return int(max(lo, min(hi, round(value))))


def _classify(score: int) -> str:
    """Map a 0-100 risk score to a classification label."""
    if score > _DANGEROUS_THRESHOLD:
        return "dangerous"
    elif score > _SUSPICIOUS_THRESHOLD:
        return "suspicious"
    else:
        return "safe"


def _generate_recommendation(
    score: int,
    classification: str,
    findings: list[Finding],
) -> str:
    """Generate a one-line human-readable recommendation."""
    if classification == "dangerous":
        # Pick the most severe finding for context
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        if critical:
            return f"⚠️ High risk — {critical[0].reason.split('—')[0].strip()}. Do not proceed."
        return "⚠️ High risk of phishing or malicious content. Do not visit this link or trust this message."

    elif classification == "suspicious":
        return "⚡ Exercise caution — some risk indicators were detected. Verify the source independently before proceeding."

    else:
        return "No significant risk indicators detected. This appears to be safe."


def compute_final_risk(
    ml_probability: float,
    findings: list[Finding],
    safe_signals: list[str] | None = None,
    scan_type: str = "url",
) -> RiskResult:
    """Combine ML probability and heuristic findings into a final risk result.

    Args:
        ml_probability: Raw ML model output (0.0 – 1.0 probability of phishing).
        findings:       List of Finding objects from the heuristic engine.
        safe_signals:   Optional list of positive-evidence strings.
        scan_type:      "url" or "email" — used for recommendation wording.

    Returns:
        A RiskResult with the final score, classification, evidence, and recommendation.
    """
    if safe_signals is None:
        safe_signals = []

    try:
        # ── Base score from ML model ────────────────────────────────────
        base_score = ml_probability * 100

        # ── Add heuristic score deltas ──────────────────────────────────
        for finding in findings:
            base_score += finding.score_delta

        # ── Critical-finding floor ──────────────────────────────────────
        has_critical = any(f.severity == Severity.CRITICAL for f in findings)
        if has_critical:
            base_score = max(base_score, _CRITICAL_FLOOR)

        # ── Clamp to 0-100 ─────────────────────────────────────────────
        final_score = _clamp(base_score)

        # ── Classification ──────────────────────────────────────────────
        classification = _classify(final_score)

        # ── Build sorted evidence list ──────────────────────────────────
        sorted_findings = sorted(
            findings,
            key=lambda f: (_SEVERITY_ORDER.get(f.severity, 99), -f.score_delta),
        )
        evidence = [
            {
                "severity": f.severity.value,
                "finding": f.reason,
            }
            for f in sorted_findings
        ]

        # Always append the ML model's own assessment as the last evidence item
        ml_pct = _clamp(ml_probability * 100)
        evidence.append(
            {
                "severity": "info",
                "finding": f"ML model confidence: {ml_pct}% phishing probability",
            }
        )

        # ── Safe signals ────────────────────────────────────────────────
        # If the score is low, prominently show positive evidence
        if classification == "safe" and not safe_signals:
            safe_signals.append(f"ML model confidence: {ml_pct}% phishing probability")

        # ── Recommendation ──────────────────────────────────────────────
        recommendation = _generate_recommendation(final_score, classification, findings)

        return RiskResult(
            risk_score=final_score,
            classification=classification,
            ml_probability=round(ml_probability * 100, 2),
            evidence=evidence,
            recommendation=recommendation,
            safe_signals=safe_signals,
        )

    except Exception:
        logger.exception("Risk engine computation failed")
        # Fail-safe: return a cautious result rather than crashing
        return RiskResult(
            risk_score=50,
            classification="suspicious",
            ml_probability=round(ml_probability * 100, 2),
            evidence=[
                {
                    "severity": "medium",
                    "finding": "Risk engine encountered an internal error — defaulting to cautious assessment",
                }
            ],
            recommendation="⚡ Unable to fully assess risk. Exercise caution.",
            safe_signals=[],
        )
