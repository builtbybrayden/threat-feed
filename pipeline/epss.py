"""FIRST EPSS enrichment (exploit prediction scores), fetched in batches."""

from __future__ import annotations

from typing import Any, Iterable

import requests


def parse_epss(payload: dict[str, Any]) -> dict[str, float]:
    """Index an EPSS API response by CVE id -> float score (unit-testable)."""
    out: dict[str, float] = {}
    for row in payload.get("data", []):
        cve = (row.get("cve") or "").upper()
        try:
            out[cve] = float(row.get("epss"))
        except (TypeError, ValueError):
            continue
    return out


def _chunks(seq: list[str], size: int) -> Iterable[list[str]]:
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


def fetch_epss(
    cve_ids: Iterable[str],
    url: str,
    session: requests.Session,
    timeout: int,
    batch_size: int = 100,
) -> dict[str, float]:
    """Fetch EPSS scores for the given CVE ids, batched to respect the API."""
    ids = sorted({c.upper() for c in cve_ids if c})
    scores: dict[str, float] = {}
    for batch in _chunks(ids, batch_size):
        resp = session.get(url, params={"cve": ",".join(batch)}, timeout=timeout)
        resp.raise_for_status()
        scores.update(parse_epss(resp.json()))
    return scores
