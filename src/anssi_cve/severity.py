"""CVSS qualitative severity rating (CVSS v3.x / v4.0 specification)."""

from __future__ import annotations


def base_severity(score: float | None) -> str | None:
    if score is None:
        return None
    score = float(score)
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"
