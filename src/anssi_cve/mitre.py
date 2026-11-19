"""Parse CVE records (CVE JSON 5.x) from the MITRE CVE Services API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests

from .config import MITRE_CVE_API
from .http import get_json
from .severity import base_severity

# Most recent CVSS version first.
_CVSS_KEYS = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")


@dataclass
class CveDetails:
    description: str | None = None
    cvss: float | None = None
    severity: str | None = None
    cwe: str | None = None
    vendor: str | None = None
    product: str | None = None
    versions: str | None = None


def _english_description(cna: dict[str, Any]) -> str | None:
    descriptions = cna.get("descriptions") or []
    for item in descriptions:
        if str(item.get("lang", "")).lower().startswith("en"):
            return item.get("value")
    return descriptions[0].get("value") if descriptions else None


def _cvss(containers: list[dict[str, Any]]) -> tuple[float | None, str | None]:
    """First CVSS score found, CNA first then ADP (e.g. CISA Vulnrichment)."""
    for container in containers:
        for metric in container.get("metrics") or []:
            for key in _CVSS_KEYS:
                data = metric.get(key)
                if data and data.get("baseScore") is not None:
                    score = float(data["baseScore"])
                    return score, data.get("baseSeverity") or base_severity(score)
    return None, None


def _cwe(containers: list[dict[str, Any]]) -> str | None:
    for container in containers:
        for problem in container.get("problemTypes") or []:
            for desc in problem.get("descriptions") or []:
                if desc.get("cweId"):
                    return desc["cweId"]
    return None


def _join_unique(values: list[str | None]) -> str | None:
    unique = list(dict.fromkeys(v for v in values if v and v not in ("n/a", "N/A")))
    return ", ".join(unique) if unique else None


def parse_cve_record(record: dict[str, Any] | None) -> CveDetails:
    if not record:
        return CveDetails()
    containers = record.get("containers", {})
    cna = containers.get("cna") or {}
    ordered = [cna, *(containers.get("adp") or [])]

    score, severity = _cvss(ordered)
    affected = cna.get("affected") or []
    versions = [
        v.get("version")
        for a in affected
        for v in a.get("versions") or []
        if v.get("status") == "affected"
    ]
    return CveDetails(
        description=_english_description(cna),
        cvss=score,
        severity=severity.upper() if severity else None,
        cwe=_cwe(ordered),
        vendor=_join_unique([a.get("vendor") for a in affected]),
        product=_join_unique([a.get("product") for a in affected]),
        versions=_join_unique(versions),
    )


def fetch_cve(session: requests.Session, cve_id: str) -> CveDetails:
    return parse_cve_record(get_json(session, MITRE_CVE_API.format(cve_id=cve_id)))
