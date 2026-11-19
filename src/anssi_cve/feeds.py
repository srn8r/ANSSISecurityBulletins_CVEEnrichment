"""Read CERT-FR RSS feeds and the JSON version of each bulletin."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import feedparser
import requests

from .http import get_json

_ANSSI_ID = re.compile(r"CERTFR-\d{4}-[A-Z]{2,4}-\d+")
_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")


@dataclass
class Bulletin:
    """A CERT-FR advisory ("Avis") or alert ("Alerte")."""

    anssi_id: str | None
    title: str
    kind: str
    published: str
    link: str
    cves: list[str] = field(default_factory=list)


def bulletin_type(link: str) -> str:
    if "/avis/" in link:
        return "Avis"
    if "/alerte/" in link:
        return "Alerte"
    return "Inconnu"


def extract_anssi_id(link: str) -> str | None:
    match = _ANSSI_ID.search(link)
    return match.group(0) if match else None


def extract_cves(bulletin_json: dict[str, Any] | None) -> list[str]:
    """Return the unique, valid CVE identifiers listed in a bulletin, in order."""
    if not bulletin_json:
        return []
    seen: dict[str, None] = {}
    for entry in bulletin_json.get("cves", []) or []:
        name = (entry or {}).get("name", "") or ""
        if _CVE_ID.fullmatch(name.strip()):
            seen.setdefault(name.strip(), None)
    return list(seen)


def json_url(link: str) -> str:
    return link.rstrip("/") + "/json/"


def read_feed(url: str, limit: int | None = None) -> list[Any]:
    feed = feedparser.parse(url)
    if feed.bozo and not feed.entries:
        raise RuntimeError(f"Unable to parse feed {url}: {feed.bozo_exception}")
    entries = list(feed.entries)
    return entries[:limit] if limit else entries


def fetch_bulletin(session: requests.Session, entry: Any) -> Bulletin:
    link = entry.link
    return Bulletin(
        anssi_id=extract_anssi_id(link),
        title=entry.get("title", ""),
        kind=bulletin_type(link),
        published=entry.get("published", ""),
        link=link,
        cves=extract_cves(get_json(session, json_url(link))),
    )
