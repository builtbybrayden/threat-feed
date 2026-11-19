"""Detection-validation artifacts: machine-written proof a template works.

A detection is only trustworthy once it has been exercised against three
controls (the protocol in ``validation/``): it MUST fire on a vulnerable
instance, MUST NOT fire on a patched build, and MUST NOT fire on a benign
endpoint. The partnering Hermes runner (on a Docker host) stands those
instances up, runs the template, applies the gate, and writes the result here
as ``validations/<CVE>/result.json``. This module loads those results so the
pipeline can surface them on the dashboard and gate deployment on a real pass.

This is distinct from ``decisions.yaml``: a *decision* is what a human recorded
(reviewed / rejected / ...); a *validation* is a machine-produced fact about a
template run. The dashboard shows both, clearly labelled, and never presents an
inferred-lab validation as a curated one.

The on-disk contract (one file per CVE, either ``validations/<CVE>/result.json``
or ``validations/<CVE>.json``)::

    {
      "cve_id": "CVE-2099-0001",
      "template": "http/cves/2099/CVE-2099-0001.yaml",   # path or template id
      "validated": true,                                  # all controls passed
      "controls": [
        {"name": "vulnerable_instance",     "expect": "detect",    "detected": true,  "pass": true},
        {"name": "patched_control",         "expect": "no-detect", "detected": false, "pass": true},
        {"name": "negative_control_benign", "expect": "no-detect", "detected": false, "pass": true}
      ],
      "lab": {
        "source": "vulhub" | "docker-hub-inference" | "custom",
        "confidence": "high" | "low",
        "vulnerable": {"image": "...", "version": "2.3.0"},
        "patched":    {"image": "...", "version": "2.3.1"},
        "note": "..."        # REQUIRED to explain any inferred (low-confidence) lab
      },
      "runner": "nuclei",
      "generated": "2026-11-01T12:00:00Z",
      "note": "Local lab only; not an independent evaluation."
    }

Loading is tolerant like ``decisions.py``: a malformed file is collected into an
errors list and skipped, never crashing the run, and never silently passing.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)

# Lab provenance. A curated vulhub environment is trustworthy ("high"); an
# inferred Docker-Hub image pair (tags guessed from the CVE's version data) is
# "low" and MUST carry a note saying so, so the UI never overstates it.
_LAB_SOURCES = {"vulhub", "docker-hub-inference", "custom"}
_CONFIDENCE = {"high", "low"}
# The three controls the protocol requires, with what each must do.
_EXPECTED_CONTROLS = {
    "vulnerable_instance": "detect",
    "patched_control": "no-detect",
    "negative_control_benign": "no-detect",
}


def _normalize_control(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError(f"control is not a mapping: {raw!r}")
    name = str(raw.get("name") or "").strip()
    if not name:
        raise ValueError("control has no name")
    detected = bool(raw.get("detected"))
    expect = str(raw.get("expect") or _EXPECTED_CONTROLS.get(name, "")).strip() or None
    # Recompute pass from expect+detected rather than trusting the file's own
    # "pass", so a result can't claim a control passed when it didn't.
    passed = raw.get("pass")
    if expect in ("detect", "no-detect"):
        passed = (detected is True) if expect == "detect" else (detected is False)
    return {"name": name, "expect": expect, "detected": detected, "pass": bool(passed)}


def _normalize_lab(raw: Any) -> dict[str, Any]:
    if raw is None:
        return {"source": "custom", "confidence": "low", "note": "no lab metadata recorded"}
    if not isinstance(raw, dict):
        raise ValueError(f"lab is not a mapping: {raw!r}")
    source = str(raw.get("source") or "custom").strip().lower()
    if source not in _LAB_SOURCES:
        raise ValueError(f"lab.source {source!r} not one of {sorted(_LAB_SOURCES)}")
    confidence = str(raw.get("confidence") or ("high" if source == "vulhub" else "low")).strip().lower()
    if confidence not in _CONFIDENCE:
        raise ValueError(f"lab.confidence {confidence!r} not one of {sorted(_CONFIDENCE)}")
    note = (raw.get("note") or "").strip() or None
    # An inferred lab must say so; synthesize a note if the writer omitted one.
    if source == "docker-hub-inference" and not note:
        note = ("Images chosen by inferring vulnerable/patched versions from the "
                "CVE — not a curated lab; the versions are supposed, not verified.")
    lab = {"source": source, "confidence": confidence, "note": note}
    for side in ("vulnerable", "patched"):
        v = raw.get(side)
        if isinstance(v, dict):
            lab[side] = {"image": v.get("image"), "version": v.get("version")}
    return lab


def normalize(raw: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Validate one result dict; return (cve_id, record) or raise ValueError.

    ``validated`` is recomputed as "all controls passed AND all three required
    controls are present", so a result can't be marked validated while missing
    the patched or benign control.
    """
    if not isinstance(raw, dict):
        raise ValueError("result is not a mapping")
    cve = str(raw.get("cve_id") or "").strip().upper()
    if not _CVE_RE.match(cve):
        raise ValueError(f"invalid/missing cve_id: {raw.get('cve_id')!r}")

    controls = [_normalize_control(c) for c in (raw.get("controls") or [])]
    names = {c["name"] for c in controls}
    missing = [n for n in _EXPECTED_CONTROLS if n not in names]
    all_pass = bool(controls) and all(c["pass"] for c in controls)
    validated = all_pass and not missing

    lab = _normalize_lab(raw.get("lab"))

    rec = {
        "cve_id": cve,
        "template": raw.get("template"),
        "validated": validated,
        "controls": controls,
        "missing_controls": missing,
        "lab": lab,
        "runner": raw.get("runner"),
        "generated": raw.get("generated"),
        "note": (raw.get("note") or "").strip() or None,
    }
    return cve, rec


def _iter_result_files(root: Path):
    """Yield result JSON files under ``root``: both ``<CVE>/result.json`` and a
    flat ``<CVE>.json`` layout are accepted."""
    if not root.exists():
        return
    for sub in sorted(root.iterdir()):
        if sub.is_dir():
            f = sub / "result.json"
            if f.exists():
                yield f
        elif sub.is_file() and sub.suffix.lower() == ".json":
            yield sub


def load_validations(path: str | Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Load validation results keyed by CVE id from a ``validations/`` directory.

    Returns (validations, errors). A missing directory is not an error (no
    validations recorded yet). A malformed file is collected into ``errors`` and
    skipped. When two files target the same CVE, the newest ``generated`` wins.
    """
    root = Path(path)
    out: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for f in _iter_result_files(root):
        try:
            with open(f, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"could not read {f}: {exc}")
            continue
        try:
            cve, rec = normalize(raw)
        except ValueError as exc:
            errors.append(f"{f.name}: {exc}")
            continue
        prev = out.get(cve)
        if prev is None or (rec.get("generated") or "") >= (prev.get("generated") or ""):
            out[cve] = rec
    return out, errors


def summarize(validations: dict[str, dict[str, Any]]) -> dict[str, int]:
    """Count validations by outcome and lab confidence (for headline stats)."""
    passed = sum(1 for v in validations.values() if v["validated"])
    failed = len(validations) - passed
    high = sum(1 for v in validations.values() if v["validated"] and v["lab"]["confidence"] == "high")
    inferred = sum(1 for v in validations.values() if v["validated"] and v["lab"]["source"] == "docker-hub-inference")
    return {
        "validated": passed,
        "validation_failed": failed,
        "validated_high_confidence": high,
        "validated_inferred_lab": inferred,
    }


def view(rec: dict[str, Any] | None) -> dict[str, Any] | None:
    """Compact validation view for the site JSON (what the dashboard renders)."""
    if not rec:
        return None
    return {
        "validated": rec["validated"],
        "controls": [{"name": c["name"], "pass": c["pass"], "detected": c["detected"]} for c in rec["controls"]],
        "missing_controls": rec.get("missing_controls") or [],
        "source": rec["lab"]["source"],
        "confidence": rec["lab"]["confidence"],
        "lab_note": rec["lab"].get("note"),
        "vulnerable": rec["lab"].get("vulnerable"),
        "patched": rec["lab"].get("patched"),
        "template": rec.get("template"),
        "runner": rec.get("runner"),
        "generated": rec.get("generated"),
    }
