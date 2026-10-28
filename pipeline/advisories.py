"""GitHub Advisory Database ingestion: recent package-ecosystem advisories.

The Threats board is otherwise seeded only from CISA KEV + CVEs named in the
news feeds, which skews it toward enterprise/OS gear. This source pulls recent
*reviewed* advisories straight from the GitHub Advisory Database, one query per
package ecosystem (PyPI, npm, Maven/Java, Go, ...) plus a cross-ecosystem
critical pull. That gives the per-ecosystem quick filters real data and makes
the board reflect application-security vulnerabilities, not just what CISA has
flagged as exploited today.

API: GET https://api.github.com/advisories (public; a GITHUB_TOKEN raises the
rate limit from 60/hr to 5000/hr and is used automatically when present).

Network functions here isolate each request so one failing ecosystem never
loses the rest (CLAUDE.md). parse_* functions are pure and unit-tested.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import requests

log = logging.getLogger("pipeline.advisories")

# GitHub advisory `ecosystem` value -> our ecosystem tag vocabulary. "pip" is
# GitHub's name for PyPI; everything else matches. Gradle has no separate GHSA
# ecosystem because Gradle builds resolve Maven coordinates, so Java/Gradle
# vulnerabilities live under "maven".
ECOSYSTEM_TAG: dict[str, str] = {
    "pip": "pypi",
    "npm": "npm",
    "maven": "maven",
    "go": "go",
    "rubygems": "rubygems",
    "nuget": "nuget",
    "composer": "composer",
    "rust": "rust",
    "erlang": "erlang",
    "actions": "actions",
    "pub": "pub",
    "swift": "swift",
}


def _cvss_from(adv: dict[str, Any]) -> tuple[Optional[float], Optional[str]]:
    """Prefer CVSS v4, then v3, then the legacy `cvss` field."""
    sev = adv.get("cvss_severities") or {}
    for key in ("cvss_v4", "cvss_v3"):
        c = sev.get(key) or {}
        if c.get("score"):
            return float(c["score"]), c.get("vector_string")
    legacy = adv.get("cvss") or {}
    if legacy.get("score"):
        return float(legacy["score"]), legacy.get("vector_string")
    return None, None


def _cve_of(adv: dict[str, Any]) -> Optional[str]:
    cve = adv.get("cve_id")
    if cve:
        return cve.upper()
    for ident in adv.get("identifiers") or []:
        if (ident.get("type") or "").upper() == "CVE" and ident.get("value"):
            return str(ident["value"]).upper()
    return None


def parse_advisory(adv: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Normalize one GHSA advisory. Returns None if it carries no CVE id.

    v1 keys CVE records by CVE id, so GHSA-only advisories (no CVE) are skipped;
    they'd be a follow-up that keys records by GHSA id too.
    """
    cve = _cve_of(adv)
    if not cve:
        return None

    ecosystems: list[str] = []
    product: Optional[str] = None
    for v in adv.get("vulnerabilities") or []:
        pkg = v.get("package") or {}
        eco = ECOSYSTEM_TAG.get((pkg.get("ecosystem") or "").lower())
        if eco and eco not in ecosystems:
            ecosystems.append(eco)
        if product is None and pkg.get("name"):
            product = pkg["name"]

    cvss_score, cvss_vector = _cvss_from(adv)

    epss: Optional[float] = None
    e = adv.get("epss") or {}
    if isinstance(e, dict) and e.get("percentage") is not None:
        try:
            epss = float(e["percentage"])
        except (TypeError, ValueError):
            epss = None

    cwes = [c.get("cwe_id") for c in (adv.get("cwes") or []) if c.get("cwe_id")]

    refs: list[dict[str, Any]] = []
    for r in adv.get("references") or []:
        url = r if isinstance(r, str) else (r.get("url") if isinstance(r, dict) else None)
        if url:
            refs.append({"url": url, "tags": ["advisory"]})
    if adv.get("html_url"):
        refs.append({"url": adv["html_url"], "tags": ["ghsa"]})

    return {
        "cve_id": cve,
        "ghsa_id": adv.get("ghsa_id"),
        "advisory_url": adv.get("html_url"),
        "summary": (adv.get("summary") or "").strip(),
        "severity": ((adv.get("severity") or "").lower() or None),
        "ecosystems": ecosystems,
        "product": product,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "epss": epss,
        "cwe": cwes,
        "references": refs,
        "published": adv.get("published_at"),
    }


def parse_advisories(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for adv in raw or []:
        parsed = parse_advisory(adv)
        if parsed:
            out.append(parsed)
    return out


def apply_to_record(rec, adv: dict[str, Any]) -> None:
    """Merge a normalized advisory into a CveRecord without clobbering richer data.

    Later NVD enrichment still wins where present (it uses `or` fallbacks); this
    makes an advisory-only CVE self-sufficient (description, CVSS, CWE, ecosystem)
    so it ranks on the board even if the NVD budget never reaches it.
    """
    if adv.get("summary") and not rec.description:
        rec.description = adv["summary"]
    if adv.get("product") and not rec.product:
        rec.product = adv["product"]
    if adv.get("cvss_score") is not None and rec.cvss_score is None:
        rec.cvss_score = adv["cvss_score"]
        rec.cvss_vector = rec.cvss_vector or adv.get("cvss_vector")
    if adv.get("epss") is not None and rec.epss is None:
        rec.epss = adv["epss"]
    if adv.get("cwe") and not rec.cwe:
        rec.cwe = list(adv["cwe"])
    if adv.get("ecosystems"):
        rec.ecosystems = sorted(set(rec.ecosystems) | set(adv["ecosystems"]))
    if adv.get("ghsa_id") and not rec.ghsa_id:
        rec.ghsa_id = adv["ghsa_id"]
    if adv.get("advisory_url") and not rec.advisory_url:
        rec.advisory_url = adv["advisory_url"]
    existing = {r.get("url") for r in rec.references}
    for r in adv.get("references", []):
        if r["url"] not in existing:
            rec.references.append(r)
            existing.add(r["url"])


def _auth_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_advisories(config: dict[str, Any], session: requests.Session, timeout: int) -> list[dict[str, Any]]:
    """Pull recent reviewed advisories per ecosystem + a cross-ecosystem critical
    pull. One page (<=100) per (ecosystem, severity) to stay polite; dedup by GHSA.
    """
    acfg = config.get("advisories", {})
    url = acfg.get("api_url", "https://api.github.com/advisories")
    severities = acfg.get("severities", ["critical", "high"])
    lookback = int(acfg.get("lookback_days", 45))
    per_eco_cap = int(acfg.get("per_ecosystem_cap", 60))
    general_cap = int(acfg.get("general_cap", 120))
    ecosystems = acfg.get(
        "ecosystems",
        ["pip", "npm", "maven", "go", "rubygems", "nuget", "composer", "rust"],
    )

    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(days=lookback)).strftime("%Y-%m-%d")
    published = f"{cutoff}..{now.strftime('%Y-%m-%d')}"
    headers = _auth_headers()

    seen: set[str] = set()
    raw: list[dict[str, Any]] = []

    def pull(params: dict[str, Any], cap: int) -> None:
        p = dict(params)
        p.update({
            "type": "reviewed",
            "per_page": min(100, cap),
            "sort": "published",
            "direction": "desc",
            "published": published,
        })
        resp = session.get(url, params=p, headers=headers, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        count = 0
        for adv in data if isinstance(data, list) else []:
            gid = adv.get("ghsa_id")
            if gid and gid in seen:
                continue
            if gid:
                seen.add(gid)
            raw.append(adv)
            count += 1
            if count >= cap:
                break

    for eco in ecosystems:
        for sev in severities:
            try:
                pull({"ecosystem": eco, "severity": sev}, per_eco_cap)
            except Exception as exc:  # per-request isolation
                log.warning("advisory pull failed: %s/%s (%s)", eco, sev, exc)

    # Cross-ecosystem critical pull: the "general high-importance AppSec" stream.
    try:
        pull({"severity": "critical"}, general_cap)
    except Exception as exc:
        log.warning("advisory general pull failed (%s)", exc)

    log.info("advisories: %d raw records across %d ecosystems", len(raw), len(ecosystems))
    return parse_advisories(raw)
