from pipeline.normalize import (
    canonical_url,
    extract_cves,
    is_safe_link,
    make_id,
    strip_html,
)


def test_strip_html_removes_tags_scripts_and_decodes_entities():
    raw = "<p>Hello <b>world</b> &amp; <script>alert(1)</script>welcome</p>"
    out = strip_html(raw)
    assert out == "Hello world & welcome"
    assert "<" not in out and "alert" not in out


def test_strip_html_handles_none_and_malformed():
    assert strip_html(None) == ""
    # Unclosed tag must not raise.
    assert "danger" in strip_html("<a href='x'>danger")


def test_extract_cves_dedupes_and_uppercases():
    text = "Affects CVE-2024-1234 and cve-2024-1234, also CVE-2021-44228."
    assert extract_cves(text) == ["CVE-2021-44228", "CVE-2024-1234"]


def test_extract_cves_ignores_non_cve_numbers():
    assert extract_cves("version 2024-1234 no prefix") == []


def test_is_safe_link_scheme_allowlist():
    assert is_safe_link("https://example.com")
    assert is_safe_link("http://example.com")
    assert not is_safe_link("javascript:alert(1)")
    assert not is_safe_link("ftp://example.com")
    assert not is_safe_link("data:text/html,x")
    assert not is_safe_link(None)


def test_canonical_url_strips_tracking_fragment_and_trailing_slash():
    a = canonical_url("https://Example.com/post/?utm_source=rss&id=7#frag")
    assert a == "https://example.com/post?id=7"


def test_make_id_is_stable_and_source_scoped():
    i1 = make_id("PortSwigger Research", "https://x.com/a/")
    i2 = make_id("PortSwigger Research", "https://x.com/a")  # canonicalizes the same
    i3 = make_id("Other Source", "https://x.com/a")
    assert i1 == i2
    assert i1 != i3
    assert len(i1) == 16
