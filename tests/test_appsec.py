from pipeline.appsec import classify_cve, classify_text
from pipeline.ingest import _classify_feed
from pipeline.models import CveRecord, Item
from pipeline.score import score_item


def _item(**kw):
    base = dict(id="i", source="PortSwigger Research", source_type="research",
                title="t", url="https://e.com", published="2000-01-01T00:00:00Z", summary="s")
    base.update(kw)
    return Item(**base)


def test_classify_text_detects_ecosystem_and_class():
    r = classify_text("New SSRF in a popular npm package")
    assert r["appsec"] is True
    assert "npm" in r["ecosystems"]
    assert "ssrf" in r["vuln_classes"]


def test_classify_text_negative_for_non_appsec():
    assert classify_text("Firmware update for an IP camera")["appsec"] is False


def test_classify_cve_via_web_cwe(config):
    rec = CveRecord(cve_id="CVE-2024-1", cwe=["CWE-89"], description="injection", product="shop")
    a = classify_cve(rec, config)
    assert a["appsec"] is True


def test_appsec_bonus_is_opt_in_and_explained(config, watchlist):
    it = _item(title="plain", summary="nothing notable")
    base, _, _ = score_item(it, config, watchlist)
    boosted, reasons, _ = score_item(it, config, watchlist, appsec=True)
    assert round(boosted - base, 1) == config["scoring"]["appsec_bonus"]
    assert any("AppSec" in r for r in reasons)


def test_feed_split_rules(config):
    # No CVE -> News.
    assert _classify_feed(_item(), config, False) == "news"
    # Multi-CVE roundup stays in News even if KEV.
    assert _classify_feed(_item(cves=["CVE-1", "CVE-2", "CVE-3"], kev=True), config, False) == "news"
    # Single KEV CVE -> Threats.
    assert _classify_feed(_item(cves=["CVE-1"], kev=True), config, False) == "threats"
    # Single AppSec CVE -> Threats.
    assert _classify_feed(_item(cves=["CVE-1"], appsec=True), config, False) == "threats"
    # Single CVE with no priority signal -> News.
    assert _classify_feed(_item(cves=["CVE-1"]), config, False) == "news"
