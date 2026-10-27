"""Detection triage: the Nuclei-pipeline intake stage.

Rules-first and explainable (CLAUDE.md): given an enriched CveRecord, decide
how detectable it is, what kind of template fits, and whether it's a
candidate (no existing template + remote/HTTP-detectable + priority signal).
"""

from __future__ import annotations

import re
from typing import Any

from .models import CveRecord, Detection

# Reference tags (NVD vocabulary) that indicate a usable writeup/exploit.
_WRITEUP_TAGS = {"Exploit", "Technical Description", "Third Party Advisory"}
_PATH_RE = re.compile(r"/[A-Za-z0-9._\-/]{3,}")


def _cwe_ints(rec: CveRecord) -> list[int]:
    out = []
    for c in rec.cwe:
        m = re.search(r"\d+", c)
        if m:
            out.append(int(m.group()))
    return out


def classify(rec: CveRecord, config: dict[str, Any]) -> Detection:
    """Populate and return rec.detection from the record's enriched fields."""
    web_cwes = set(config.get("web_cwes", []))
    det = rec.detection

    vector = rec.cvss_vector or ""
    det.remote_network = "AV:N" in vector

    cwe_http = any(c in web_cwes for c in _cwe_ints(rec))
    app_cpe = any(":a:" in cpe for cpe in rec.cpes)
    det.likely_http = cwe_http or (det.remote_network and app_cpe)

    det.has_poc = bool(rec.poc_links)
    det.has_technical_writeup = any(
        set(ref.get("tags", [])) & _WRITEUP_TAGS for ref in rec.references
    )

    # Behavioural template only when we have something to model it on AND the
    # issue is HTTP-shaped; otherwise fall back to the safer passive fingerprint.
    if det.likely_http and (det.has_poc or det.has_technical_writeup):
        det.suggested_template_type = "behavioral"
    else:
        det.suggested_template_type = "version-fingerprint"

    det.fingerprint_hints = _fingerprint_hints(rec)
    det.test_target_hint = _test_target_hint(rec)
    return det


def _fingerprint_hints(rec: CveRecord) -> list[str]:
    """Best-effort passive detection hints from product + references."""
    hints: list[str] = []
    if rec.product:
        hints.append(
            f"Fingerprint {rec.vendor or ''} {rec.product} via Server/X-Powered-By "
            "headers, a /version or /about endpoint, or a static asset hash."
        )
    if rec.affected_versions or rec.fixed_version:
        hints.append(
            f"Affected: {rec.affected_versions or '?'}; fixed in: "
            f"{rec.fixed_version or '?'} — match versions below the fix."
        )
    # Surface a couple of path-looking tokens from the description as leads.
    paths = sorted(set(_PATH_RE.findall(rec.description)))[:3]
    if paths:
        hints.append("Paths mentioned in description: " + ", ".join(paths))
    return hints


def _test_target_hint(rec: CveRecord) -> str | None:
    if rec.product:
        return f"Look for a vulhub lab under '{rec.product}' or the vendor advisory for a repro."
    return None


def evaluate_candidate(
    rec: CveRecord, config: dict[str, Any], *, watchlist_hit: bool
) -> tuple[bool, list[str]]:
    """Apply the candidate rule and return (is_candidate, reasons)."""
    reasons: list[str] = []
    threshold = config.get("candidate", {}).get("epss_threshold", 0.3)

    has_template = rec.nuclei_template is not None
    detectable = rec.detection.remote_network or rec.detection.likely_http
    priority = rec.kev or (rec.epss is not None and rec.epss >= threshold) or watchlist_hit

    if has_template:
        reasons.append(f"template already exists: {rec.nuclei_template}")
    if not detectable:
        reasons.append("not clearly remote/HTTP-detectable")

    is_candidate = (not has_template) and detectable and priority
    if is_candidate:
        if rec.detection.likely_http:
            reasons.append("HTTP-detectable (web CWE/CPE)")
        elif rec.detection.remote_network:
            reasons.append("remote (AV:N)")
        if rec.kev:
            reasons.append("in CISA KEV")
        if rec.epss is not None and rec.epss >= threshold:
            reasons.append(f"EPSS {rec.epss:.0%} >= {threshold:.0%}")
        if watchlist_hit:
            reasons.append("watchlist product")
        reasons.append("no existing Nuclei template")

    return is_candidate, reasons
