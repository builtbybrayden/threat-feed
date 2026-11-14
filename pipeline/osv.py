"""OSV.dev ingestion: the language-ecosystem vulnerability databases.

GHSA (advisories.py) covers the GitHub-reviewed package ecosystems well, but the
dedicated language databases — RustSec (crates.io), the Go vulnerability DB, Hex
(Elixir/Erlang), Pub (Dart) — are only partly mirrored there. OSV.dev aggregates
all of them under one schema, so this module adds them as a discovery stream,
keyed (like every other source) by the CVE id in each record's ``aliases``.

How we consume it (bounded on purpose):
  * OSV publishes per-ecosystem exports in a public GCS bucket as ``<eco>/all.zip``.
    We pull ONLY the small language-DB ecosystems (crates.io ~4 MB, Go ~13 MB,
    Hex ~1 MB, Pub ~30 KB) — never npm (~220 MB) or PyPI (~38 MB), which GHSA
    already covers and which would dwarf the run. Each zip is one request.
  * The zip is UNTRUSTED (CLAUDE.md): read in memory via ZipFile.read only (no
    extraction, so no path traversal), with caps on the download size, per-member
    uncompressed size, and total bytes read (decompression-bomb guards).
  * We keep only records whose ``modified`` date falls within a recent lookback
    window, so one bounded download yields a bounded, recent record set.

Pure functions (parse_record / parse_records / records_from_zip_bytes) take data
and are unit-tested with no network; fetch_recent isolates each ecosystem's
request so one failure never loses the rest.
"""

from __future__ import annotations

import io
import json
import logging
import re
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import requests

from .models import CveRecord
from .util import to_utc_iso

log = logging.getLogger("pipeline.osv")

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)

# OSV ecosystem name -> our ecosystem tag vocabulary. OSV ecosystem strings can
# carry a suffixed variant (e.g. "Alpine:v3.16"); we match on the base before ":".
OSV_ECOSYSTEM_TAG: dict[str, str] = {
    "crates.io": "rust",
    "go": "go",
    "hex": "hex",
    "pub": "pub",
    "pypi": "pypi",
    "npm": "npm",
    "maven": "maven",
    "rubygems": "rubygems",
    "nuget": "nuget",
    "packagist": "composer",
}


def _cve_of(raw: dict[str, Any]) -> Optional[str]:
    for alias in raw.get("aliases") or []:
        a = str(alias).strip().upper()
        if _CVE_RE.match(a):
            return a
    return None


def _ecosystem_tag(raw: dict[str, Any]) -> Optional[str]:
    for aff in raw.get("affected") or []:
        eco = ((aff.get("package") or {}).get("ecosystem") or "").split(":", 1)[0].strip().lower()
        if eco:
            return OSV_ECOSYSTEM_TAG.get(eco, eco)
    return None


def _product(raw: dict[str, Any]) -> Optional[str]:
    for aff in raw.get("affected") or []:
        name = (aff.get("package") or {}).get("name")
        if name:
            return str(name)
    return None


def _cvss_vector(raw: dict[str, Any]) -> Optional[str]:
    """OSV severity entries carry a CVSS *vector* (not a numeric score). Prefer v4,
    then v3. The numeric base score is left to NVD/GHSA enrichment."""
    sev = raw.get("severity") or []
    for want in ("CVSS_V4", "CVSS_V3"):
        for s in sev:
            if (s.get("type") or "").upper() == want and s.get("score"):
                return str(s["score"])
    return None


def _versions(raw: dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
    """Best-effort (affected_versions, fixed_version) from OSV ranges/versions.

    OSV encodes version data as ``affected[].ranges[].events[]`` (``introduced`` /
    ``fixed`` / ``last_affected``) plus an optional exact ``affected[].versions``
    list. ``fixed_version`` is the first ``fixed`` event — the "supposed safe"
    version the Docker-Hub lab fallback uses; ``affected_versions`` is a readable
    range for the "supposed vulnerable" side. Both are best-effort, not authoritative.
    """
    fixed: Optional[str] = None
    introduced: Optional[str] = None
    last_affected: Optional[str] = None
    exact: list[str] = []
    for aff in raw.get("affected") or []:
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed") and not fixed:
                    fixed = str(ev["fixed"])
                if ev.get("introduced") and introduced is None:
                    introduced = str(ev["introduced"])
                if ev.get("last_affected") and not last_affected:
                    last_affected = str(ev["last_affected"])
        for v in (aff.get("versions") or []):
            exact.append(str(v))
    if fixed and introduced in (None, "0"):
        affected = f"< {fixed}"
    elif fixed and introduced:
        affected = f">= {introduced}, < {fixed}"
    elif last_affected:
        affected = f"<= {last_affected}"
    elif introduced:
        affected = f">= {introduced}"
    elif exact:
        affected = ", ".join(exact[:5]) + ("…" if len(exact) > 5 else "")
    else:
        affected = None
    return affected, fixed


def _cwes(raw: dict[str, Any]) -> list[str]:
    ds = raw.get("database_specific") or {}
    out = []
    for c in ds.get("cwe_ids") or []:
        if c and c not in out:
            out.append(str(c))
    return out


def _references(raw: dict[str, Any]) -> list[dict[str, Any]]:
    refs = []
    for r in raw.get("references") or []:
        url = r.get("url") if isinstance(r, dict) else (r if isinstance(r, str) else None)
        if url:
            tag = (r.get("type") or "").lower() if isinstance(r, dict) else ""
            refs.append({"url": url, "tags": [tag] if tag else ["osv"]})
    return refs


def parse_record(raw: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Normalize one OSV record. Returns None when it has no CVE alias (v1 keys by
    CVE) or has been withdrawn."""
    if not isinstance(raw, dict):
        return None
    if raw.get("withdrawn"):
        return None  # OSV marks retracted records with a `withdrawn` timestamp
    cve = _cve_of(raw)
    if not cve:
        return None
    description = (raw.get("summary") or "").strip() or (raw.get("details") or "").strip()
    eco = _ecosystem_tag(raw)
    affected_versions, fixed_version = _versions(raw)
    return {
        "cve_id": cve,
        "source": "osv",
        "osv_id": raw.get("id"),
        "description": description,
        "product": _product(raw),
        "ecosystems": [eco] if eco else [],
        "affected_versions": affected_versions,
        "fixed_version": fixed_version,
        "cvss_vector": _cvss_vector(raw),
        "cwe": _cwes(raw),
        "references": _references(raw),
        "published": to_utc_iso(raw["published"]) if raw.get("published") else None,
        "modified": to_utc_iso(raw["modified"]) if raw.get("modified") else None,
    }


def parse_records(
    raw_list: list[dict[str, Any]], *, since: Optional[str] = None, cap: Optional[int] = None
) -> list[dict[str, Any]]:
    """Normalize many OSV records; drop CVE-less/withdrawn ones; keep only those
    modified on/after ``since`` (a UTC ISO string); cap the result. Pure."""
    out: list[dict[str, Any]] = []
    for raw in raw_list or []:
        data = parse_record(raw)
        if data is None:
            continue
        if since and (not data["modified"] or data["modified"] < since):
            continue
        out.append(data)
        if cap is not None and len(out) >= cap:
            break
    return out


def records_from_zip_bytes(
    blob: bytes,
    *,
    since: Optional[str] = None,
    cap: Optional[int] = None,
    max_entry_bytes: int = 1024 * 1024,
    max_total_bytes: int = 256 * 1024 * 1024,
) -> list[dict[str, Any]]:
    """Parse OSV records out of an ``all.zip`` held in memory, with the same
    untrusted-zip guards as the CVE-List intake (read-only, size-capped)."""
    raws: list[dict[str, Any]] = []
    total = 0
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
    except zipfile.BadZipFile as exc:
        log.warning("osv: export is not a valid zip (%s)", exc)
        return []
    with zf:
        for info in zf.infolist():
            if info.is_dir() or not info.filename.lower().endswith(".json"):
                continue
            if info.file_size > max_entry_bytes:
                continue
            total += info.file_size
            if total > max_total_bytes:
                log.warning("osv: export exceeded %d uncompressed bytes — stopping", max_total_bytes)
                break
            try:
                raws.append(json.loads(zf.read(info)))
            except (ValueError, OSError):
                continue
    return parse_records(raws, since=since, cap=cap)


def apply_to_record(rec: CveRecord, data: dict[str, Any]) -> None:
    """Merge a normalized OSV record into a CveRecord without clobbering richer
    data; NVD/GHSA still win where present. Unions ecosystems and references."""
    if data.get("description") and not rec.description:
        rec.description = data["description"]
    if data.get("product") and not rec.product:
        rec.product = data["product"]
    if data.get("affected_versions") and not rec.affected_versions:
        rec.affected_versions = data["affected_versions"]
    if data.get("fixed_version") and not rec.fixed_version:
        rec.fixed_version = data["fixed_version"]
    if data.get("cvss_vector") and not rec.cvss_vector:
        rec.cvss_vector = data["cvss_vector"]
    if data.get("cwe") and not rec.cwe:
        rec.cwe = list(data["cwe"])
    if data.get("ecosystems"):
        rec.ecosystems = sorted(set(rec.ecosystems) | set(data["ecosystems"]))
    if data.get("published") and not rec.published:
        rec.published = data["published"]
    if data.get("modified") and (not rec.modified or data["modified"] > rec.modified):
        rec.modified = data["modified"]
    existing = {r.get("url") for r in rec.references}
    for r in data.get("references", []):
        if r["url"] not in existing:
            rec.references.append(r)
            existing.add(r["url"])


def _download_capped(url: str, session: requests.Session, timeout: int, max_bytes: int) -> Optional[bytes]:
    with session.get(url, timeout=timeout, stream=True) as resp:
        resp.raise_for_status()
        clen = resp.headers.get("Content-Length")
        if clen and int(clen) > max_bytes:
            log.warning("osv: export Content-Length %s exceeds cap %d — skipping", clen, max_bytes)
            return None
        buf = bytearray()
        for chunk in resp.iter_content(chunk_size=65536):
            buf.extend(chunk)
            if len(buf) > max_bytes:
                log.warning("osv: export exceeded %d bytes mid-download — aborting", max_bytes)
                return None
        return bytes(buf)


def fetch_recent(config: dict[str, Any], session: requests.Session, timeout: int) -> list[dict[str, Any]]:
    """Download the configured per-ecosystem OSV exports and return normalized
    records modified within the lookback window (deduped by CVE, newest kept)."""
    oc = config.get("osv", {})
    bucket = oc.get("bucket_url", "https://osv-vulnerabilities.storage.googleapis.com")
    ecosystems = oc.get("ecosystems", ["crates.io", "Go", "Hex", "Pub"])
    lookback = int(oc.get("lookback_days", 45))
    cap = int(oc.get("max_records", 300))
    max_zip = int(oc.get("max_zip_bytes", 52428800))      # 50 MiB per-ecosystem guard
    max_entry = int(oc.get("max_entry_bytes", 1048576))   # 1 MiB per-record guard

    since = (datetime.now(timezone.utc) - timedelta(days=lookback)).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Keep the newest record per CVE across ecosystems (a CVE can appear in more
    # than one), so the merged result has no duplicate CVE ids.
    by_cve: dict[str, dict[str, Any]] = {}
    for eco in ecosystems:
        url = f"{bucket}/{eco}/all.zip"
        try:
            blob = _download_capped(url, session, timeout, max_zip)
        except Exception as exc:  # per-ecosystem isolation
            log.warning("osv: fetch failed for %s (%s)", eco, exc)
            continue
        if blob is None:
            continue
        recs = records_from_zip_bytes(blob, since=since, max_entry_bytes=max_entry)
        for data in recs:
            cur = by_cve.get(data["cve_id"])
            if cur is None or (data["modified"] or "") > (cur["modified"] or ""):
                by_cve[data["cve_id"]] = data
        log.info("osv: %s -> %d recent records", eco, len(recs))

    out = sorted(by_cve.values(), key=lambda d: d["modified"] or "", reverse=True)
    return out[:cap]
