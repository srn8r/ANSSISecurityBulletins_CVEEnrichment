"""Exploit Prediction Scoring System (EPSS) scores from the FIRST API."""

from __future__ import annotations

from collections.abc import Iterable

import requests

from .config import EPSS_BATCH_SIZE, FIRST_EPSS_API
from .http import get_json


def parse_epss_response(payload: dict | None) -> dict[str, float]:
    scores: dict[str, float] = {}
    for item in (payload or {}).get("data", []) or []:
        try:
            scores[item["cve"]] = float(item["epss"])
        except (KeyError, TypeError, ValueError):
            continue
    return scores


def fetch_epss(session: requests.Session, cve_ids: Iterable[str]) -> dict[str, float]:
    """Fetch EPSS scores in batches (one request per 100 CVEs instead of one per CVE)."""
    ids = sorted(set(cve_ids))
    scores: dict[str, float] = {}
    for start in range(0, len(ids), EPSS_BATCH_SIZE):
        batch = ids[start : start + EPSS_BATCH_SIZE]
        scores.update(parse_epss_response(get_json(session, FIRST_EPSS_API, cve=",".join(batch))))
    return scores
