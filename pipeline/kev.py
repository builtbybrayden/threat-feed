"""CISA Known Exploited Vulnerabilities (KEV) catalog ingestion."""

from __future__ import annotations

from typing import Any

import requests


def parse_kev(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Index a KEV catalog dict by CVE id (unit-testable; no network)."""
    out: dict[str, dict[str, Any]] = {}
    for vuln in data.get("vulnerabilities", []):
        cve = (vuln.get("cveID") or "").upper()
        if not cve:
            continue
        out[cve] = {
            "vendor": vuln.get("vendorProject"),
            "product": vuln.get("product"),
            "name": vuln.get("vulnerabilityName"),
            "date_added": vuln.get("dateAdded"),
            "due_date": vuln.get("dueDate"),
            "known_ransomware": vuln.get("knownRansomwareCampaignUse"),
        }
    return out


def fetch_kev(url: str, session: requests.Session, timeout: int) -> dict[str, dict[str, Any]]:
    resp = session.get(url, timeout=timeout)
    resp.raise_for_status()
    return parse_kev(resp.json())
