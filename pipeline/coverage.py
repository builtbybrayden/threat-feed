"""Nuclei template coverage index: which CVEs already have a template.

The index maps CVE id -> template path (relative to the nuclei-templates
repo). It is built by walking a local clone and reading each template's
`id` and `info.classification.cve-id`, with the filename as a fallback. The
result is cached to JSON so we don't re-clone/re-walk every pipeline run.

Build/refresh the index (shallow clone handled by the Makefile / CI):
    python -m pipeline.coverage --templates ./nuclei-templates --out cache/coverage_index.json
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _cves_from_template(path: Path) -> list[str]:
    """Extract CVE ids a template covers: classification first, then id/filename."""
    cves: set[str] = set()
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            doc = yaml.safe_load(fh)
    except (yaml.YAMLError, OSError):
        doc = None

    if isinstance(doc, dict):
        info = doc.get("info", {}) or {}
        classification = info.get("classification", {}) or {}
        cid = classification.get("cve-id")
        if isinstance(cid, str):
            cves.update(_CVE_RE.findall(cid))
        elif isinstance(cid, list):
            for c in cid:
                if isinstance(c, str):
                    cves.update(_CVE_RE.findall(c))
        tid = doc.get("id")
        if isinstance(tid, str):
            cves.update(_CVE_RE.findall(tid))

    # Fallback: the filename itself is very often the CVE id.
    cves.update(_CVE_RE.findall(path.stem))
    return [c.upper() for c in cves]


def build_index(templates_dir: str | Path) -> dict[str, str]:
    """Walk a nuclei-templates checkout and map CVE id -> relative template path."""
    root = Path(templates_dir)
    index: dict[str, str] = {}
    for path in root.rglob("*.yaml"):
        rel = path.relative_to(root).as_posix()
        for cve in _cves_from_template(path):
            # First template wins; CVE-path templates are typically canonical.
            index.setdefault(cve, rel)
    return index


# A cached index is stored in one of two on-disk shapes, both accepted here:
#   1. a flat mapping   {"CVE-...": "path", ...}              (legacy / sample_data)
#   2. an envelope       {"meta": {...}, "index": {"CVE-...": "path", ...}}
# The envelope lets us record *when* the index was built and from which source,
# so the pipeline can tell "no template indexed" apart from "no index available"
# (a missing or stale index must never be reported as a confirmed coverage gap).


def _split(data: Any) -> tuple[dict[str, str], dict[str, Any]]:
    if isinstance(data, dict) and "index" in data and isinstance(data["index"], dict):
        return data["index"], (data.get("meta") or {})
    if isinstance(data, dict):
        return data, {}
    return {}, {}


def load_index(path: str | Path) -> dict[str, str]:
    """Load a cached coverage index, or return {} if it doesn't exist yet.

    Accepts both the flat and the enveloped on-disk shapes. An empty dict means
    "no index available", which the caller must not treat as "no templates".
    """
    p = Path(path)
    if not p.exists():
        return {}
    with open(p, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    index, _ = _split(data)
    return {k.upper(): v for k, v in index.items()}


def load_index_meta(path: str | Path) -> dict[str, Any]:
    """Return provenance for a cached index: whether it is available, when it was
    built, how many CVE-covering templates it holds, and its source. ``available``
    is False when the file is missing or holds no entries, so a run with no index
    reports coverage as *unknown* rather than inventing confirmed gaps."""
    p = Path(path)
    if not p.exists():
        return {"available": False, "as_of": None, "template_count": 0, "source": None}
    try:
        with open(p, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {"available": False, "as_of": None, "template_count": 0, "source": None}
    index, meta = _split(data)
    return {
        "available": len(index) > 0,
        "as_of": meta.get("as_of"),
        "template_count": meta.get("template_count", len(index)),
        "source": meta.get("source"),
    }


def save_index(index: dict[str, str], path: str | Path, meta: dict[str, Any] | None = None) -> None:
    """Persist the index. With ``meta`` the enveloped shape is written (recording
    provenance); without it the flat shape is kept for backward compatibility."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if meta is None:
        payload: Any = index
    else:
        full_meta = {"as_of": _now_iso(), "template_count": len(index), **meta}
        payload = {"meta": full_meta, "index": index}
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2, sort_keys=True)


def _main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build the Nuclei coverage index.")
    ap.add_argument("--templates", required=True, help="path to a nuclei-templates checkout")
    ap.add_argument("--out", default="cache/coverage_index.json")
    args = ap.parse_args(argv)
    index = build_index(args.templates)
    save_index(index, args.out, meta={"source": str(args.templates)})
    print(f"Indexed {len(index)} CVE-covering templates -> {args.out}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
