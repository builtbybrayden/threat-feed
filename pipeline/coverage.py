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
from pathlib import Path
from typing import Any

import yaml

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


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


def load_index(path: str | Path) -> dict[str, str]:
    """Load a cached coverage index, or return {} if it doesn't exist yet."""
    p = Path(path)
    if not p.exists():
        return {}
    with open(p, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return {k.upper(): v for k, v in data.items()}


def save_index(index: dict[str, str], path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(index, fh, ensure_ascii=False, indent=2, sort_keys=True)


def _main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build the Nuclei coverage index.")
    ap.add_argument("--templates", required=True, help="path to a nuclei-templates checkout")
    ap.add_argument("--out", default="cache/coverage_index.json")
    args = ap.parse_args(argv)
    index = build_index(args.templates)
    save_index(index, args.out)
    print(f"Indexed {len(index)} CVE-covering templates -> {args.out}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
