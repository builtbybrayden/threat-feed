"""Fetch and normalize RSS/Atom feeds into Item objects.

We fetch bytes with our own session (so timeouts/retries/UA apply) and hand
them to feedparser, rather than letting feedparser fetch, which gives us no
timeout control. Each feed is parsed independently; the orchestrator isolates
failures so one dead source can't fail the run.
"""

from __future__ import annotations

from typing import Any

import feedparser
import requests

from .models import Item
from .normalize import extract_cves, is_safe_link, make_id, strip_html
from .util import to_utc_iso


def _entry_guid(entry: Any) -> str:
    """Pick the most stable identifier a feed entry offers."""
    return (
        getattr(entry, "id", None)
        or getattr(entry, "guid", None)
        or getattr(entry, "link", None)
        or getattr(entry, "title", "")
    )


def _entry_summary(entry: Any) -> str:
    # Prefer full content when present, else the summary; both get HTML-stripped.
    content = getattr(entry, "content", None)
    if content and isinstance(content, list) and content:
        raw = content[0].get("value", "")
    else:
        raw = getattr(entry, "summary", "") or getattr(entry, "description", "")
    return strip_html(raw)


def parse_feed_bytes(raw: bytes, feed: dict[str, Any]) -> list[Item]:
    """Parse already-fetched feed bytes into Items (no network; unit-testable)."""
    parsed = feedparser.parse(raw)
    items: list[Item] = []
    for entry in parsed.entries:
        link = getattr(entry, "link", "") or ""
        if not is_safe_link(link):
            # Drop entries whose primary link isn't http(s); nothing to point at.
            continue
        title = strip_html(getattr(entry, "title", "")) or "(untitled)"
        summary = _entry_summary(entry)
        published = to_utc_iso(
            getattr(entry, "published_parsed", None)
            or getattr(entry, "updated_parsed", None)
            or getattr(entry, "published", None)
        )
        guid = _entry_guid(entry)
        items.append(
            Item(
                id=make_id(feed["name"], guid),
                source=feed["name"],
                source_type=feed.get("type", "news"),
                title=title,
                url=link,
                published=published,
                summary=summary,
                cves=extract_cves(title, summary),
            )
        )
    return items


def fetch_feed(feed: dict[str, Any], session: requests.Session, timeout: int) -> list[Item]:
    """Fetch one feed over the network and return normalized Items.

    Raises on network/HTTP error; the caller is expected to isolate failures.
    """
    resp = session.get(feed["url"], timeout=timeout)
    resp.raise_for_status()
    return parse_feed_bytes(resp.content, feed)
