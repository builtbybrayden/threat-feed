"""Transparent, config-driven scoring. Every contribution is explained.

The dashboard shows score_reasons[] verbatim, so each term we add here is
phrased for a human reading "why this scored high".
"""

from __future__ import annotations

from typing import Any

from .models import Item
from .util import age_days, word_boundary_hits


def score_item(
    item: Item,
    config: dict[str, Any],
    watchlist: list[str],
    *,
    has_poc: bool = False,
    appsec: bool = False,
) -> tuple[float, list[str], list[str]]:
    """Return (score, score_reasons, watchlist_hits) for an item.

    watchlist_hits is returned so the caller can also tag the item without
    re-scanning the text.
    """
    s = config.get("scoring", {})
    reasons: list[str] = []
    total = 0.0

    # Source weight: trust some feeds more than others.
    weights = s.get("source_weights", {})
    sw = weights.get(item.source, s.get("default_source_weight", 5))
    total += sw
    reasons.append(f"source:{item.source} (+{sw})")

    # Actively exploited.
    if item.kev:
        b = s.get("kev_bonus", 40)
        total += b
        reasons.append(f"in CISA KEV (+{b})")

    # Likelihood of exploitation in the wild.
    if item.epss is not None:
        contrib = round(item.epss * s.get("epss_weight", 30), 1)
        if contrib:
            total += contrib
            reasons.append(f"EPSS {item.epss:.0%} (+{contrib})")

    # Watchlist relevance (scored once regardless of how many terms hit).
    hits = word_boundary_hits(f"{item.title} {item.summary}", watchlist)
    if hits:
        b = s.get("watchlist_bonus", 15)
        total += b
        reasons.append(f"watchlist:{','.join(hits[:3])} (+{b})")

    # Public proof-of-concept exists.
    if has_poc:
        b = s.get("poc_bonus", 10)
        total += b
        reasons.append(f"has PoC (+{b})")

    # Application-security relevance (this repo's focus).
    if appsec:
        b = s.get("appsec_bonus", 14)
        total += b
        reasons.append(f"AppSec-relevant (+{b})")

    # Recency decay: fresh items float up.
    rec = s.get("recency", {})
    half_life = rec.get("half_life_days", 7)
    max_bonus = rec.get("max_bonus", 15)
    if half_life > 0:
        contrib = round(max_bonus * 0.5 ** (age_days(item.published) / half_life), 1)
        if contrib >= 0.1:
            total += contrib
            reasons.append(f"recency (+{contrib})")

    lo, hi = s.get("clamp", [0, 100])
    total = max(lo, min(hi, total))
    return round(total, 1), reasons, hits


def score_cve(rec, config: dict[str, Any]) -> float:
    """Intrinsic priority score for a CVE record (used to rank the detection queue).

    A CVE often has no feed item linking it (e.g. a KEV entry no outlet covered),
    so it can't borrow an item's score. This derives a score from the CVE's own
    signals so the queue still ranks by real priority.
    """
    s = config.get("scoring", {})
    total = 0.0
    if rec.kev:
        total += s.get("kev_bonus", 40)
    if rec.epss is not None:
        total += rec.epss * s.get("epss_weight", 30)
    if rec.poc_links:
        total += s.get("poc_bonus", 10)
    if getattr(rec, "appsec", False):
        total += s.get("appsec_bonus", 14)
    if rec.cvss_score is not None:
        total += float(rec.cvss_score)  # 0–10, nudges severe issues up
    lo, hi = s.get("clamp", [0, 100])
    return round(max(lo, min(hi, total)), 1)
