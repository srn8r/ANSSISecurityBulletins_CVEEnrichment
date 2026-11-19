"""Shared HTTP session with timeouts and automatic retries."""

from __future__ import annotations

from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .config import REQUEST_TIMEOUT, USER_AGENT


def build_session(retries: int = 3, backoff: float = 0.5) -> requests.Session:
    """Return a session that retries on transient errors and rate limiting."""
    retry = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET",),
        respect_retry_after_header=True,
    )
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json"})
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def get_json(session: requests.Session, url: str, **params: Any) -> dict[str, Any] | None:
    """GET a JSON document. Returns None on 404, raises on other HTTP errors."""
    response = session.get(url, params=params or None, timeout=REQUEST_TIMEOUT)
    if response.status_code == 404:
        return None
    response.raise_for_status()
    return response.json()
