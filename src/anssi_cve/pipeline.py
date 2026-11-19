"""End-to-end pipeline: feeds -> bulletins -> CVE enrichment -> DataFrame."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd
import requests

from .config import COLUMNS, FEEDS
from .epss import fetch_epss
from .feeds import Bulletin, fetch_bulletin, read_feed
from .mitre import CveDetails, fetch_cve

log = logging.getLogger(__name__)


def collect_bulletins(
    session: requests.Session,
    feed_names: Iterable[str],
    limit: int | None = None,
    workers: int = 8,
) -> list[Bulletin]:
    entries = []
    for name in feed_names:
        feed_entries = read_feed(FEEDS[name], limit=limit)
        log.info("Feed %s: %d bulletins", name, len(feed_entries))
        entries.extend(feed_entries)

    bulletins: list[Bulletin] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(fetch_bulletin, session, e): e for e in entries}
        for future in as_completed(futures):
            try:
                bulletins.append(future.result())
            except Exception as exc:  # one broken bulletin must not stop the run
                log.warning("Skipping %s: %s", futures[future].link, exc)
    return bulletins


def enrich_cves(
    session: requests.Session, cve_ids: Iterable[str], workers: int = 8
) -> dict[str, CveDetails]:
    """Fetch each unique CVE once, even if it appears in several bulletins."""
    unique = sorted(set(cve_ids))
    details: dict[str, CveDetails] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(fetch_cve, session, cve): cve for cve in unique}
        for future in as_completed(futures):
            cve = futures[future]
            try:
                details[cve] = future.result()
            except Exception as exc:
                log.warning("MITRE lookup failed for %s: %s", cve, exc)
                details[cve] = CveDetails()
    return details


def build_rows(
    bulletins: Iterable[Bulletin],
    details: dict[str, CveDetails],
    epss: dict[str, float],
) -> list[dict]:
    rows = []
    for b in bulletins:
        for cve in b.cves or [None]:  # keep bulletins that reference no CVE
            d = details.get(cve, CveDetails()) if cve else CveDetails()
            rows.append(
                {
                    "ID ANSSI": b.anssi_id,
                    "Titre ANSSI": b.title,
                    "Type": b.kind,
                    "Date": b.published,
                    "CVE": cve,
                    "CVSS": d.cvss,
                    "Base Severity": d.severity,
                    "CWE": d.cwe,
                    "EPSS": epss.get(cve) if cve else None,
                    "Lien": b.link,
                    "Description": d.description,
                    "Éditeur": d.vendor,
                    "Produit": d.product,
                    "Versions affectées": d.versions,
                }
            )
    return rows


def to_dataframe(rows: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(rows, columns=COLUMNS)
    df["Date"] = pd.to_datetime(df["Date"], errors="coerce", utc=True)
    return df.sort_values(["Date", "ID ANSSI", "CVE"], ascending=[False, True, True]).reset_index(
        drop=True
    )


def run(
    session: requests.Session,
    feed_names: Iterable[str] = FEEDS,
    limit: int | None = None,
    workers: int = 8,
) -> pd.DataFrame:
    bulletins = collect_bulletins(session, feed_names, limit=limit, workers=workers)
    all_cves = {cve for b in bulletins for cve in b.cves}
    log.info("%d bulletins, %d unique CVEs", len(bulletins), len(all_cves))
    details = enrich_cves(session, all_cves, workers=workers)
    epss = fetch_epss(session, all_cves)
    return to_dataframe(build_rows(bulletins, details, epss))
