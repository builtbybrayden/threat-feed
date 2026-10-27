"""The two normalized schemas: Item (a feed entry) and CveRecord (a CVE).

Plain dataclasses with explicit (de)serialization so state.json and the
site JSON have a stable, documented shape. Keeping (de)serialization here
means tests can round-trip without touching disk or the network.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional


@dataclass
class Item:
    """One normalized entry from a feed (news/research) or the KEV catalog."""

    id: str                       # sha256(source | canonical_url_or_guid)[:16]
    source: str                   # e.g. "PortSwigger Research"
    source_type: str              # "research" | "news" | "kev"
    title: str
    url: str
    published: str                # UTC ISO 8601, e.g. "2026-10-27T14:29:26Z"
    summary: str                  # plain text, HTML already stripped
    cves: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    score: float = 0.0
    score_reasons: list[str] = field(default_factory=list)
    kev: bool = False
    epss: Optional[float] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Item":
        # Tolerate extra/missing keys so old state files still load.
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class Detection:
    """Rules-first detectability assessment for a CVE (the Nuclei intake)."""

    remote_network: bool = False          # CVSS AV:N
    likely_http: bool = False             # web CPE or a web CWE
    has_poc: bool = False
    has_technical_writeup: bool = False
    suggested_template_type: str = "version-fingerprint"  # or "behavioral"
    fingerprint_hints: list[str] = field(default_factory=list)
    test_target_hint: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Detection":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class CveRecord:
    """Everything known about a single CVE, keyed by CVE id."""

    cve_id: str
    description: str = ""
    cwe: list[str] = field(default_factory=list)
    cvss_vector: Optional[str] = None
    cvss_score: Optional[float] = None
    vendor: Optional[str] = None
    product: Optional[str] = None
    cpes: list[str] = field(default_factory=list)
    affected_versions: Optional[str] = None
    fixed_version: Optional[str] = None
    references: list[dict[str, Any]] = field(default_factory=list)  # {url, tags[]}
    kev: bool = False
    epss: Optional[float] = None
    poc_links: list[str] = field(default_factory=list)
    nuclei_template: Optional[str] = None          # path in nuclei-templates, or None
    detection: Detection = field(default_factory=Detection)
    is_candidate: bool = False
    candidate_reasons: list[str] = field(default_factory=list)
    score: float = 0.0                              # best score of linked items
    issue_number: Optional[int] = None
    first_seen: Optional[str] = None
    last_updated: Optional[str] = None
    nvd_fetched_at: Optional[str] = None            # for enrichment cache TTL

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["detection"] = self.detection.to_dict()
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CveRecord":
        d = dict(d)
        det = d.get("detection")
        d["detection"] = Detection.from_dict(det) if isinstance(det, dict) else Detection()
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})
