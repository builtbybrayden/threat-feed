"""Auditable detection-decision records: the lifecycle a candidate moves through.

Triage (triage.py) decides whether a CVE is a *candidate*. What a human then did
about it — reviewed it, validated a detection in a lab, shipped it, rejected it,
or found it inconclusive — is recorded here, by hand, in a single `decisions.yaml`
file at the repo root. The pipeline merges these records onto the CVE records so
the dashboard and the queue show a real decision trail (who, when, why, with what
artifacts), not just "candidate / not candidate".

The model is deliberately the simplest thing that is auditable:

    - cve: CVE-2099-0001
      status: lab-validated          # see LIFECYCLE_STATES
      reviewer: Brayden Arnold
      date: 2026-11-01               # ISO date of the decision
      rationale: >
        HTTP-detectable path traversal, public PoC; worth a behavioural check.
      template: validation/example_path_traversal/detection.yaml
      artifacts:
        - validation/example_path_traversal/result.json
      outcome: >
        Detected on the vulnerable instance; clean on the patched control and on
        the negative-control endpoint. See result.json.
      notes: Local lab only (authorised).

Nothing here fabricates outcomes: a record states only what a human recorded.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

# The lifecycle. The first four are the forward path; the last two are terminal
# outcomes that are NOT successes (so a decision trail can honestly end in "we
# decided not to" or "we couldn't tell").
LIFECYCLE_STATES = [
    "candidate",      # identified by triage, not yet looked at by a human
    "reviewed",       # a human reviewed it and decided it is worth pursuing
    "lab-validated",  # a detection was validated locally (vuln + patched + negative)
    "completed",      # detection shipped / merged upstream / otherwise closed out
    "rejected",       # a human decided not to build a detection (with a reason)
    "inconclusive",   # investigated but detectability/validation was not established
]
_TERMINAL = {"completed", "rejected", "inconclusive"}
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
_KNOWN_FIELDS = {
    "cve", "status", "reviewer", "date", "rationale",
    "template", "reference", "artifacts", "outcome", "notes",
}


def is_terminal(status: str) -> bool:
    return status in _TERMINAL


def _normalize(raw: dict[str, Any], idx: int) -> tuple[str, dict[str, Any]]:
    """Validate one record; return (cve_id, record) or raise ValueError."""
    if not isinstance(raw, dict):
        raise ValueError(f"decision #{idx} is not a mapping")
    cve = str(raw.get("cve", "")).strip().upper()
    if not _CVE_RE.match(cve):
        raise ValueError(f"decision #{idx} has an invalid/missing cve: {raw.get('cve')!r}")
    status = str(raw.get("status", "")).strip()
    if status not in LIFECYCLE_STATES:
        raise ValueError(
            f"{cve}: status {status!r} not one of {LIFECYCLE_STATES}"
        )
    artifacts = raw.get("artifacts") or []
    if isinstance(artifacts, str):
        artifacts = [artifacts]
    unknown = set(raw) - _KNOWN_FIELDS
    if unknown:
        raise ValueError(f"{cve}: unknown field(s) {sorted(unknown)}")
    # YAML parses an unquoted ISO date as a datetime.date; coerce to a string so
    # the record stays JSON-serializable (it ends up in site/*.json).
    date = raw.get("date")
    rec = {
        "status": status,
        "reviewer": raw.get("reviewer"),
        "date": str(date) if date is not None else None,
        "rationale": (raw.get("rationale") or "").strip() or None,
        "template": raw.get("template"),
        "reference": raw.get("reference"),
        "artifacts": [str(a) for a in artifacts],
        "outcome": (raw.get("outcome") or "").strip() or None,
        "notes": (raw.get("notes") or "").strip() or None,
        "terminal": is_terminal(status),
    }
    return cve, rec


def load_decisions(path: str | Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Load decision records keyed by CVE id.

    Returns (decisions, errors). A missing file is not an error — it means no
    decisions have been recorded yet, which is the correct empty default. Malformed
    records are collected into ``errors`` and skipped, so one bad record never
    discards the rest (and never silently passes either).
    """
    p = Path(path)
    if not p.exists():
        return {}, []
    try:
        with open(p, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except (yaml.YAMLError, OSError) as exc:
        return {}, [f"could not read {p}: {exc}"]
    if data is None:
        return {}, []
    if not isinstance(data, list):
        return {}, [f"{p}: expected a list of decision records, got {type(data).__name__}"]

    decisions: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for idx, raw in enumerate(data):
        try:
            cve, rec = _normalize(raw, idx)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if cve in decisions:
            errors.append(f"{cve}: duplicate decision record (keeping the first)")
            continue
        decisions[cve] = rec
    return decisions, errors


def summarize(decisions: dict[str, dict[str, Any]]) -> dict[str, int]:
    """Count recorded decisions per lifecycle state (missing states report 0)."""
    counts = {s: 0 for s in LIFECYCLE_STATES}
    for rec in decisions.values():
        counts[rec["status"]] = counts.get(rec["status"], 0) + 1
    return counts
