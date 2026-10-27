"""Normalization helpers: HTML stripping, CVE extraction, id hashing, URLs.

Feed content is UNTRUSTED (CLAUDE.md security requirements). We:
  * strip all HTML to plain text in Python (the site then renders via
    textContent only, never innerHTML),
  * only ever keep http/https links,
  * derive a stable id so re-runs dedupe cleanly.

Uses only the Python standard library (no bs4) to honour the stack constraint.
"""

from __future__ import annotations

import hashlib
import re
from html import unescape
from html.parser import HTMLParser
from urllib.parse import urlsplit, urlunsplit

# CVE ids: CVE-YYYY-NNNN+ (4+ digits). Case-insensitive; we upper-case on output.
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Tracking/query junk we drop so the same article from two feeds dedupes.
_STRIP_QUERY_PREFIXES = ("utm_", "ref", "fbclid", "gclid", "mc_")


class _TextExtractor(HTMLParser):
    """Collect visible text, dropping tags, scripts and styles entirely."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._chunks: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: object) -> None:
        if tag in ("script", "style"):
            self._skip += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self._chunks.append(data)

    def text(self) -> str:
        return "".join(self._chunks)


def strip_html(raw: str | None) -> str:
    """Return plain text with HTML removed and entities decoded, whitespace collapsed."""
    if not raw:
        return ""
    parser = _TextExtractor()
    try:
        parser.feed(raw)
        parser.close()
        text = parser.text()
    except Exception:
        # Malformed markup must never crash the run; fall back to a crude strip.
        text = re.sub(r"<[^>]+>", " ", raw)
    text = unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def extract_cves(*texts: str | None) -> list[str]:
    """Return a sorted, de-duplicated list of CVE ids found in the given texts."""
    found: set[str] = set()
    for t in texts:
        if not t:
            continue
        for m in _CVE_RE.findall(t):
            found.add(m.upper())
    return sorted(found)


def is_safe_link(url: str | None) -> bool:
    """Only http/https links are ever rendered or stored as references."""
    if not url:
        return False
    try:
        scheme = urlsplit(url).scheme.lower()
    except ValueError:
        return False
    return scheme in ("http", "https")


def canonical_url(url: str | None) -> str:
    """Normalize a URL for deduping: drop fragments and tracking query params."""
    if not url:
        return ""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return url.strip()
    query_pairs = [
        pair
        for pair in parts.query.split("&")
        if pair and not pair.lower().startswith(_STRIP_QUERY_PREFIXES)
    ]
    netloc = parts.netloc.lower()
    path = parts.path.rstrip("/") or "/"
    return urlunsplit((parts.scheme.lower(), netloc, path, "&".join(query_pairs), ""))


def make_id(source: str, url_or_guid: str) -> str:
    """Stable 16-hex id from source + canonical url/guid (dedupe key)."""
    basis = f"{source}|{canonical_url(url_or_guid) or url_or_guid}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]
