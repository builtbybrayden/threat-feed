import pytest

from pipeline import feeds as feeds_mod
from pipeline.feeds import parse_feed_bytes
from pipeline.ingest import gather_feed_items

RSS = b"""<?xml version="1.0"?>
<rss version="2.0"><channel>
  <title>Example Research</title>
  <item>
    <title>Critical bug in Confluence (CVE-2024-1234)</title>
    <link>https://example.com/blog/confluence-bug</link>
    <guid>https://example.com/blog/confluence-bug</guid>
    <pubDate>Mon, 27 Oct 2026 10:00:00 GMT</pubDate>
    <description>&lt;p&gt;Details about &lt;b&gt;CVE-2024-1234&lt;/b&gt;.&lt;/p&gt;</description>
  </item>
  <item>
    <title>Non-http link entry</title>
    <link>javascript:alert(1)</link>
    <description>should be dropped</description>
  </item>
</channel></rss>"""

FEED = {"name": "Example Research", "type": "research"}


def test_parse_feed_bytes_extracts_fields_and_cves():
    items = parse_feed_bytes(RSS, FEED)
    # The javascript: entry is dropped; only the safe one survives.
    assert len(items) == 1
    it = items[0]
    assert it.source == "Example Research"
    assert it.source_type == "research"
    assert it.url == "https://example.com/blog/confluence-bug"
    assert it.cves == ["CVE-2024-1234"]
    assert "<" not in it.summary  # HTML stripped
    assert it.published.endswith("Z")


def test_parse_feed_bytes_survives_garbage():
    # Malformed input must not raise.
    assert parse_feed_bytes(b"not xml at all", FEED) == []


def test_gather_feed_items_isolates_a_broken_source():
    """One dead source must never fail the run (CLAUDE.md)."""
    cfg = {
        "http": {"timeout": 5},
        "feeds": [
            {"name": "good", "type": "news", "url": "https://good"},
            {"name": "bad", "type": "news", "url": "https://bad"},
        ],
    }

    def fake_fetch(feed, session, timeout):
        if feed["name"] == "bad":
            raise RuntimeError("boom")
        return parse_feed_bytes(RSS, {"name": "good", "type": "news"})

    orig = feeds_mod.fetch_feed
    feeds_mod.fetch_feed = fake_fetch
    try:
        items = gather_feed_items(cfg, session=object(), offline=False, sample_dir=None)
    finally:
        feeds_mod.fetch_feed = orig

    # The good source's items are present; the bad one is skipped silently.
    assert len(items) == 1
    assert items[0].source == "good"
