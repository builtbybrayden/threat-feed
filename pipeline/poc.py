"""Proof-of-concept signals from the nomi-sec PoC-in-GitHub index.

That project publishes one JSON file per year (e.g. 2024/CVE-2024-1234.json)
listing GitHub repos that reference the CVE. A 404 simply means "no known PoC".
We also treat NVD references tagged "Exploit" as a PoC signal (handled by the
orchestrator, which has the references); this module covers the GitHub index.
"""

from __future__ import annotations

from typing import Any

import requests


def parse_poc(payload: Any) -> list[str]:
    """Extract http(s) PoC repo URLs from a nomi-sec per-CVE JSON payload."""
    links: list[str] = []
    if isinstance(payload, list):
        for repo in payload:
            url = repo.get("html_url") if isinstance(repo, dict) else None
            if url and url.startswith("http"):
                links.append(url)
    return links


def fetch_poc(cve_id: str, base_url: str, session: requests.Session, timeout: int) -> list[str]:
    """Return known PoC repo URLs for a CVE. Empty list if none / not found."""
    cve_id = cve_id.upper()
    try:
        year = cve_id.split("-")[1]
    except IndexError:
        return []
    resp = session.get(f"{base_url}/{year}/{cve_id}.json", timeout=timeout)
    if resp.status_code == 404:
        return []
    resp.raise_for_status()
    try:
        return parse_poc(resp.json())
    except ValueError:
        return []
