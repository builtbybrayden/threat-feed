"""Persistent state: items seen and CVE records, so re-runs dedupe and cache.

state.json is the single source of truth between runs. It holds every Item
we've ever seen (keyed by id) and every CveRecord (keyed by CVE id). The site
JSON is a derived, trimmed view produced each run from this.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .models import CveRecord, Item
from .util import now_iso


class State:
    def __init__(self) -> None:
        self.items: dict[str, Item] = {}
        self.cves: dict[str, CveRecord] = {}
        self.meta: dict[str, Any] = {}

    # --- load / save -----------------------------------------------------
    @classmethod
    def load(cls, path: str | Path) -> "State":
        st = cls()
        p = Path(path)
        if not p.exists():
            return st
        with open(p, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        st.items = {k: Item.from_dict(v) for k, v in data.get("items", {}).items()}
        st.cves = {k: CveRecord.from_dict(v) for k, v in data.get("cves", {}).items()}
        st.meta = data.get("meta", {})
        return st

    def save(self, path: str | Path) -> None:
        self.meta["last_run"] = now_iso()
        data = {
            "items": {k: v.to_dict() for k, v in self.items.items()},
            "cves": {k: v.to_dict() for k, v in self.cves.items()},
            "meta": self.meta,
        }
        _atomic_write_json(path, data)

    # --- mutation --------------------------------------------------------
    def upsert_item(self, item: Item) -> bool:
        """Insert or refresh an item. Returns True if it was new."""
        is_new = item.id not in self.items
        if not is_new:
            # Preserve the original first-seen ordering; refresh everything else.
            pass
        self.items[item.id] = item
        return is_new

    def get_cve(self, cve_id: str) -> CveRecord:
        """Fetch or create the CveRecord for a CVE id."""
        cve_id = cve_id.upper()
        rec = self.cves.get(cve_id)
        if rec is None:
            rec = CveRecord(cve_id=cve_id, first_seen=now_iso())
            self.cves[cve_id] = rec
        return rec


def _atomic_write_json(path: str | Path, data: Any) -> None:
    """Write JSON atomically so a crash mid-write can't corrupt the file."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=p.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2, sort_keys=True)
        os.replace(tmp, p)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
