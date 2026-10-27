"""Shared helpers: config/watchlist loading, time handling, HTTP session."""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
import yaml
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

ROOT = Path(__file__).resolve().parent.parent


def load_yaml(path: str | Path) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load_config(path: str | Path = ROOT / "config.yaml") -> dict[str, Any]:
    return load_yaml(path)


def load_watchlist(path: str | Path = ROOT / "watchlist.yaml") -> list[str]:
    data = load_yaml(path)
    return [str(t).lower() for t in data.get("terms", [])]


def now_iso() -> str:
    """Current time as UTC ISO 8601 with a trailing Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def to_utc_iso(value: Any) -> str:
    """Best-effort conversion of a feed time (struct_time, datetime, or str) to UTC ISO.

    Falls back to the current time if nothing parseable is given, so an item
    always has a usable timestamp for recency scoring and sorting.
    """
    if value is None:
        return now_iso()
    # feedparser gives a time.struct_time (already UTC) as *_parsed.
    if isinstance(value, time.struct_time):
        return datetime(*value[:6], tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(value, str):
        v = value.strip()
        # Handle the common ISO forms, including a trailing Z.
        try:
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
            dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            pass
    return now_iso()


def age_days(iso: str, *, reference: datetime | None = None) -> float:
    """Age in days of a UTC ISO timestamp; 0 if it can't be parsed or is in the future."""
    ref = reference or datetime.now(timezone.utc)
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return 0.0
    return max(0.0, (ref - dt).total_seconds() / 86400.0)


def make_session(config: dict[str, Any]) -> requests.Session:
    """A requests Session with timeouts (via caller), retries and backoff.

    One dead source must never fail the whole run (CLAUDE.md), so callers wrap
    requests in try/except; this just makes transient failures self-heal.
    """
    http = config.get("http", {})
    session = requests.Session()
    retry = Retry(
        total=http.get("retries", 3),
        backoff_factor=http.get("backoff_factor", 1.5),
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET", "HEAD"),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({"User-Agent": http.get("user_agent", "threat-feed/0.1")})
    return session


def word_boundary_hits(text: str, terms: list[str]) -> list[str]:
    """Return which watchlist terms appear as whole words in text (case-insensitive)."""
    if not text:
        return []
    low = text.lower()
    hits = []
    for term in terms:
        # \b doesn't work around terms with spaces/punctuation uniformly, so we
        # build a boundary-ish pattern: term must be flanked by non-word chars.
        pattern = r"(?<![a-z0-9])" + re.escape(term) + r"(?![a-z0-9])"
        if re.search(pattern, low):
            hits.append(term)
    return hits
