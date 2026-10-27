#!/usr/bin/env python3
"""Snapshot a trimmed, representative sample_data/ set from a real state.json.

The live site (site/data.json, site/candidates.json) is produced from the full
online run. sample_data/ is a smaller snapshot committed so `--offline` works
with no network for local dev and a disconnected demo; it keeps every feed item
plus a representative slice of KEV CVEs (all candidates + CVEs referenced by
items + the highest-EPSS KEV entries).

    python tools/make_sample.py            # reads ./state.json
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOP_KEV_BY_EPSS = 120


def main() -> None:
    state = json.loads((ROOT / "state.json").read_text(encoding="utf-8"))
    items = list(state["items"].values())
    cves = state["cves"]

    # Which CVEs to include in the snapshot.
    referenced = {c for it in items for c in it.get("cves", [])}
    candidates = {cid for cid, r in cves.items() if r.get("is_candidate")}
    kev_by_epss = sorted(
        (cid for cid, r in cves.items() if r.get("kev")),
        key=lambda cid: cves[cid].get("epss") or 0,
        reverse=True,
    )[:TOP_KEV_BY_EPSS]
    keep = referenced | candidates | set(kev_by_epss)
    keep &= set(cves)

    out = ROOT / "sample_data"
    out.mkdir(parents=True, exist_ok=True)

    def dump(name, obj):
        (out / name).write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")

    dump("items.json", items)
    dump("kev.json", {"vulnerabilities": [
        {"cveID": cid, "vendorProject": cves[cid].get("vendor"), "product": cves[cid].get("product")}
        for cid in keep if cves[cid].get("kev")
    ]})
    dump("epss.json", {"data": [
        {"cve": cid, "epss": str(cves[cid]["epss"])}
        for cid in keep if cves[cid].get("epss") is not None
    ]})
    dump("nvd.json", {
        cid: {
            "description": cves[cid].get("description", ""),
            "cwe": cves[cid].get("cwe", []),
            "cvss_vector": cves[cid].get("cvss_vector"),
            "cvss_score": cves[cid].get("cvss_score"),
            "vendor": cves[cid].get("vendor"),
            "product": cves[cid].get("product"),
            "cpes": cves[cid].get("cpes", []),
            "references": cves[cid].get("references", []),
        }
        for cid in keep if cves[cid].get("description")
    })
    dump("poc.json", {cid: cves[cid]["poc_links"] for cid in keep if cves[cid].get("poc_links")})
    dump("coverage_index.json", {cid: cves[cid]["nuclei_template"]
                                 for cid in keep if cves[cid].get("nuclei_template")})

    print(f"sample_data: {len(items)} items, {len(keep)} CVEs snapshotted -> {out}")


if __name__ == "__main__":
    main()
