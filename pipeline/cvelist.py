"""MITRE CVE List v5 ingestion: the authoritative CVE record stream.

GHSA only sees CVEs that have a GitHub advisory, and NVD has run a large
enrichment backlog since 2024, so both miss freshly-assigned CVEs. The CVE List
(github.com/CVEProject/cvelistV5) is the source of record: every CVE, published
by its CNA, in CVE JSON 5.x. This module adds it as a discovery stream so a
webapp CVE shows up here the day its CNA publishes it, not whenever NVD gets to
it.

How we consume it (bounded on purpose):
  * The repo publishes an hourly GitHub *Release*. Each release carries a small
    ``*_delta_CVEs_at_*.zip`` (~1-2 MB, the records changed since midnight UTC)
    alongside a ~650 MB ``all_CVEs`` bundle. We fetch ONLY the delta zip — one
    request, no 650 MB download, no per-record fan-out, no cloning 300k files.
  * The downloaded zip is UNTRUSTED (CLAUDE.md): we never extract to disk (so no
    path traversal), we cap the download size, the per-entry uncompressed size,
    and the total bytes read (so no decompression bomb), and we read each member
    into memory via ZipFile.read only.
  * We keep only webapp/appsec-relevant records (the stated scope), reusing the
    shared appsec classifier so "relevant" means the same thing everywhere.

Pure functions (parse_record / parse_records / records_from_zip_bytes) take data
and are unit-tested with no network; the fetch_* functions isolate every network
call so one failure never fails the run.
"""

from __future__ import annotations

import io
import logging
import os
import zipfile
from typing import Any, Optional

import requests

from . import appsec as appsec_mod
from .models import CveRecord
from .util import to_utc_iso

log = logging.getLogger("pipeline.cvelist")

# CVE JSON 5.x metric blocks, in the order we prefer them (newest scheme first).
_CVSS_KEYS = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV3", "cvssV2_0")


def _descriptions(container: dict[str, Any]) -> str:
    """English description text from a CNA/ADP container (first en entry)."""
    for d in container.get("descriptions") or []:
        if (d.get("lang") or "").lower().startswith("en") and d.get("value"):
            return str(d["value"]).strip()
    # Fall back to the first description of any language rather than nothing.
    for d in container.get("descriptions") or []:
        if d.get("value"):
            return str(d["value"]).strip()
    return ""


def _cwes(container: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for pt in container.get("problemTypes") or []:
        for d in pt.get("descriptions") or []:
            cwe = d.get("cweId")
            if cwe and cwe not in out:
                out.append(cwe)
    return out


def _cvss_from(container: dict[str, Any]) -> tuple[Optional[float], Optional[str]]:
    """Best (score, vector) from a container's ``metrics`` list, newest scheme first."""
    metrics = container.get("metrics") or []
    for key in _CVSS_KEYS:
        for m in metrics:
            block = m.get(key) if isinstance(m, dict) else None
            if isinstance(block, dict) and block.get("baseScore") is not None:
                try:
                    return float(block["baseScore"]), block.get("vectorString")
                except (TypeError, ValueError):
                    continue
    return None, None


def _affected(container: dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
    """First real (vendor, product) from ``affected`` ("n/a" placeholders dropped)."""
    for a in container.get("affected") or []:
        vendor = (a.get("vendor") or "").strip()
        product = (a.get("product") or "").strip()
        vendor = vendor if vendor and vendor.lower() != "n/a" else None
        product = product if product and product.lower() != "n/a" else None
        if vendor or product:
            return vendor, product
    return None, None


def _references(container: dict[str, Any]) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for r in container.get("references") or []:
        url = r.get("url") if isinstance(r, dict) else (r if isinstance(r, str) else None)
        if url:
            tags = list(r.get("tags") or []) if isinstance(r, dict) else []
            refs.append({"url": url, "tags": tags or ["cvelist"]})
    return refs


def parse_record(raw: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Normalize one CVE 5.x record. Returns None for a non-PUBLISHED record
    (REJECTED/placeholder) or one with no CVE id — nothing to track."""
    if not isinstance(raw, dict):
        return None
    meta = raw.get("cveMetadata") or {}
    cve = str(meta.get("cveId") or "").strip().upper()
    if not cve:
        return None
    state = (meta.get("state") or "").upper()
    if state and state != "PUBLISHED":
        return None  # REJECTED (or RESERVED leaking through) carries no usable vuln data

    containers = raw.get("containers") or {}
    cna = containers.get("cna") or {}
    adps = containers.get("adp") or []
    if not isinstance(adps, list):
        adps = []

    description = _descriptions(cna) or (cna.get("title") or "").strip()

    # CWE and CVSS may live in the CNA container or in an ADP container (e.g.
    # CISA-ADP adds metrics/SSVC). Prefer the CNA, fall back to ADP.
    cwe = _cwes(cna)
    for adp in adps:
        for c in _cwes(adp):
            if c not in cwe:
                cwe.append(c)

    cvss_score, cvss_vector = _cvss_from(cna)
    if cvss_score is None:
        for adp in adps:
            cvss_score, cvss_vector = _cvss_from(adp)
            if cvss_score is not None:
                break

    vendor, product = _affected(cna)

    refs = _references(cna)
    seen = {r["url"] for r in refs}
    for adp in adps:
        for r in _references(adp):
            if r["url"] not in seen:
                refs.append(r)
                seen.add(r["url"])

    return {
        "cve_id": cve,
        "source": "cvelist",
        "title": (cna.get("title") or "").strip() or None,
        "description": description,
        "vendor": vendor,
        "product": product,
        "cwe": cwe,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "references": refs,
        "published": to_utc_iso(meta.get("datePublished")) if meta.get("datePublished") else None,
        "modified": to_utc_iso(meta.get("dateUpdated")) if meta.get("dateUpdated") else None,
        "assigner": meta.get("assignerShortName"),
    }


def is_webapp_relevant(data: dict[str, Any]) -> bool:
    """Whether a normalized record is application-security / webapp relevant.

    Reuses the shared appsec vocabulary so "relevant" means the same thing here
    as everywhere else in the pipeline: a web/appsec CWE, or ecosystem/vuln-class
    keywords in the text (description/product/vendor)."""
    import re

    cwe_ids = {int(m.group()) for c in data.get("cwe", []) if (m := re.search(r"\d+", c))}
    if cwe_ids & appsec_mod.APPSEC_CWES:
        return True
    text = appsec_mod.classify_text(
        data.get("description"), data.get("product"), data.get("vendor"), " ".join(data.get("cwe", []))
    )
    return bool(text["appsec"])


def parse_records(
    raw_list: list[dict[str, Any]], *, webapp_only: bool = True, cap: Optional[int] = None
) -> list[dict[str, Any]]:
    """Normalize many CVE 5.x records; drop REJECTED and (by default) non-webapp
    records; cap the result. Pure — no network, no disk."""
    out: list[dict[str, Any]] = []
    for raw in raw_list or []:
        data = parse_record(raw)
        if data is None:
            continue
        if webapp_only and not is_webapp_relevant(data):
            continue
        out.append(data)
        if cap is not None and len(out) >= cap:
            break
    return out


def records_from_zip_bytes(
    blob: bytes,
    *,
    webapp_only: bool = True,
    cap: Optional[int] = None,
    max_entry_bytes: int = 2 * 1024 * 1024,
    max_total_bytes: int = 256 * 1024 * 1024,
) -> list[dict[str, Any]]:
    """Parse CVE records out of a delta zip held in memory.

    The zip is untrusted: we read members with ZipFile.read only (never extract,
    so a crafted name can't escape a directory), we skip any member whose declared
    uncompressed size exceeds ``max_entry_bytes``, and we stop once the running
    uncompressed total passes ``max_total_bytes`` (decompression-bomb guard)."""
    raws: list[dict[str, Any]] = []
    total = 0
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
    except zipfile.BadZipFile as exc:
        log.warning("cvelist: delta bundle is not a valid zip (%s)", exc)
        return []
    with zf:
        for info in zf.infolist():
            if info.is_dir() or not info.filename.lower().endswith(".json"):
                continue
            if info.filename.rsplit("/", 1)[-1].lower() == "delta.json":
                continue  # the bundle's own manifest, not a CVE record
            if info.file_size > max_entry_bytes:
                log.warning("cvelist: skipping oversized zip member %s (%d bytes)", info.filename, info.file_size)
                continue
            total += info.file_size
            if total > max_total_bytes:
                log.warning("cvelist: delta bundle exceeded %d uncompressed bytes — stopping", max_total_bytes)
                break
            try:
                import json
                raws.append(json.loads(zf.read(info)))
            except (ValueError, OSError) as exc:
                log.warning("cvelist: could not read member %s (%s)", info.filename, exc)
                continue
    return parse_records(raws, webapp_only=webapp_only, cap=cap)


def apply_to_record(rec: CveRecord, data: dict[str, Any]) -> None:
    """Merge a normalized CVE-List record into a CveRecord without clobbering
    richer data. Like advisories, later NVD enrichment still wins where present;
    this makes a CVE-List-only record self-sufficient so it can rank and triage."""
    if data.get("description") and not rec.description:
        rec.description = data["description"]
    if data.get("vendor") and not rec.vendor:
        rec.vendor = data["vendor"]
    if data.get("product") and not rec.product:
        rec.product = data["product"]
    if data.get("cvss_score") is not None and rec.cvss_score is None:
        rec.cvss_score = data["cvss_score"]
        rec.cvss_vector = rec.cvss_vector or data.get("cvss_vector")
    if data.get("cwe") and not rec.cwe:
        rec.cwe = list(data["cwe"])
    if data.get("published") and not rec.published:
        rec.published = data["published"]
    if data.get("modified") and (not rec.modified or data["modified"] > rec.modified):
        rec.modified = data["modified"]
    existing = {r.get("url") for r in rec.references}
    for r in data.get("references", []):
        if r["url"] not in existing:
            rec.references.append(r)
            existing.add(r["url"])


def _gh_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _download_capped(url: str, session: requests.Session, timeout: int, max_bytes: int) -> Optional[bytes]:
    """Download a URL, refusing to buffer more than ``max_bytes`` (guards against a
    mis-identified huge asset)."""
    with session.get(url, timeout=timeout, stream=True) as resp:
        resp.raise_for_status()
        clen = resp.headers.get("Content-Length")
        if clen and int(clen) > max_bytes:
            log.warning("cvelist: asset Content-Length %s exceeds cap %d — skipping", clen, max_bytes)
            return None
        buf = bytearray()
        for chunk in resp.iter_content(chunk_size=65536):
            buf.extend(chunk)
            if len(buf) > max_bytes:
                log.warning("cvelist: asset exceeded %d bytes mid-download — aborting", max_bytes)
                return None
        return bytes(buf)


def fetch_recent(config: dict[str, Any], session: requests.Session, timeout: int) -> list[dict[str, Any]]:
    """Find the newest release carrying a bounded delta bundle, download just that
    bundle, and return normalized (webapp-filtered) records."""
    cc = config.get("cvelist", {})
    releases_url = cc.get("releases_url", "https://api.github.com/repos/CVEProject/cvelistV5/releases")
    asset_match = cc.get("asset_match", "_delta_CVEs_")
    scan = int(cc.get("releases_to_scan", 10))
    max_zip = int(cc.get("max_zip_bytes", 25 * 1024 * 1024))
    cap = int(cc.get("max_records", 400))
    max_entry = int(cc.get("max_entry_bytes", 2 * 1024 * 1024))
    webapp_only = bool(cc.get("webapp_only", True))

    resp = session.get(releases_url, params={"per_page": scan}, headers=_gh_headers(), timeout=timeout)
    resp.raise_for_status()
    releases = resp.json()
    if not isinstance(releases, list):
        return []

    for rel in releases:
        for asset in rel.get("assets", []) or []:
            name = asset.get("name") or ""
            # The delta bundle only — never the ~650 MB all-CVEs zip.
            if asset_match not in name or "all_CVEs" in name:
                continue
            if asset.get("size") and int(asset["size"]) > max_zip:
                continue
            url = asset.get("browser_download_url")
            if not url:
                continue
            try:
                blob = _download_capped(url, session, timeout, max_zip)
            except Exception as exc:
                log.warning("cvelist: delta download failed for %s (%s)", name, exc)
                return []
            if blob is None:
                continue
            records = records_from_zip_bytes(
                blob, webapp_only=webapp_only, cap=cap, max_entry_bytes=max_entry
            )
            log.info("cvelist: %s -> %d webapp-relevant records", name, len(records))
            return records
    log.info("cvelist: no delta bundle found in the %d most recent releases", scan)
    return []
