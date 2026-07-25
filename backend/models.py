"""
Shared data models for the ThreatLens risk-scoring pipeline.

These dataclasses are the common language between the heuristic engine,
risk engine, and API response layer. Every module that produces or consumes
heuristic findings uses these types.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    """Severity tier for a heuristic finding.

    Ordering matters: CRITICAL findings trigger a score floor (≥85).
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def sort_key(self) -> int:
        """Lower number = higher severity (for sorting evidence lists)."""
        return {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
        }[self]


@dataclass(frozen=True)
class Finding:
    """A single piece of evidence produced by the heuristic engine.

    Attributes:
        name:        Short machine-readable identifier, e.g. "ip_address_domain".
        severity:    One of critical / high / medium / low.
        score_delta: How many points this finding adds to the base ML score.
        reason:      Human-readable explanation shown in the API response.
    """

    name: str
    severity: Severity
    score_delta: int
    reason: str


@dataclass
class RiskResult:
    """Final combined risk assessment returned by the risk engine.

    This is what the API endpoint serializes into JSON.
    """

    risk_score: int  # 0–100
    classification: str  # "safe" | "suspicious" | "dangerous"
    ml_probability: float  # 0–100, raw ML model output
    evidence: list[dict]  # [{"severity": "...", "finding": "..."}]
    recommendation: str  # One-line human-readable advice
    safe_signals: list[str] = field(default_factory=list)  # Positive evidence


@dataclass
class SafeSignal:
    """A positive trust indicator (shown when score is low)."""

    reason: str
