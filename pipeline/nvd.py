"""NVD API 2.0 enrichment: description, CWE, CVSS vector, CPEs, references.

NVD rate-limits hard, especially without an API key, so the orchestrator
throttles calls and the enrichment is cached in state (see cache_ttl). An
NVD_API_KEY env var is used when present but never required.
"""

from __future__ import annotations

import os
import time
from typing import Any

import requests

NVD_API_KEY_ENV = "NVD_API_KEY"


def _best_cvss(metrics: dict[str, Any]) -> tuple[str | None, float | None]:
    """Pick the most authoritative CVSS vector/score available (v3.1 > v3.0 > v2)."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            return data.get("vectorString"), data.get("baseScore")
    return None, None


def parse_cve(payload: dict[str, Any]) -> dict[str, Any]:
    """Parse an NVD 2.0 response for a single CVE into enrichment fields.

    Pure/unit-testable: hand it the parsed JSON, get a dict back.
    """
    vulns = payload.get("vulnerabilities") or []
    if not vulns:
        return {}
    cve = vulns[0].get("cve", {})

    # Prefer the English description.
    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break

    cwe: list[str] = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-") and val not in cwe:
                cwe.append(val)

    vector, base_score = _best_cvss(cve.get("metrics", {}))

    # CPEs + a best-effort vendor/product from the first applicable CPE.
    cpes: list[str] = []
    vendor = product = None
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for match in node.get("cpeMatch", []):
                crit = match.get("criteria")
                if crit and crit not in cpes:
                    cpes.append(crit)
                    if vendor is None:
                        parts = crit.split(":")  # cpe:2.3:a:vendor:product:...
                        if len(parts) > 4:
                            vendor, product = parts[3], parts[4]

    references = []
    for ref in cve.get("references", []):
        url = ref.get("url")
        if url:
            references.append({"url": url, "tags": ref.get("tags", [])})

    return {
        "description": description,
        "cwe": cwe,
        "cvss_vector": vector,
        "cvss_score": base_score,
        "vendor": vendor,
        "product": product,
        "cpes": cpes[:25],  # cap to keep state.json reasonable
        "references": references,
    }


def fetch_cve(cve_id: str, url: str, session: requests.Session, timeout: int) -> dict[str, Any]:
    """Fetch and parse one CVE from NVD. Honors NVD_API_KEY if set."""
    headers = {}
    key = os.environ.get(NVD_API_KEY_ENV)
    if key:
        headers["apiKey"] = key
    resp = session.get(url, params={"cveId": cve_id}, headers=headers, timeout=timeout)
    resp.raise_for_status()
    return parse_cve(resp.json())


def throttle_delay(config: dict[str, Any]) -> float:
    """Seconds to sleep between NVD calls, depending on whether a key is set."""
    nvd = config.get("nvd", {})
    if os.environ.get(NVD_API_KEY_ENV):
        return nvd.get("delay_with_key", 0.8)
    return nvd.get("delay_no_key", 6.5)


def sleep(seconds: float) -> None:
    # Wrapped so tests can monkeypatch it instead of actually waiting.
    time.sleep(seconds)
