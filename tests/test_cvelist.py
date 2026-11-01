import io
import json
import zipfile

from pipeline.cvelist import (
    apply_to_record,
    is_webapp_relevant,
    parse_record,
    parse_records,
    records_from_zip_bytes,
)
from pipeline.models import CveRecord


def _record(cve="CVE-2099-7101", state="PUBLISHED", cwe="CWE-89", desc="SQL injection over HTTP",
            score_key="cvssV3_1", score=9.8):
    return {
        "cveMetadata": {
            "cveId": cve, "state": state, "assignerShortName": "demo",
            "datePublished": "2026-10-28T09:00:00.000Z", "dateUpdated": "2026-10-29T09:00:00.000Z",
        },
        "containers": {
            "cna": {
                "title": "A bug",
                "descriptions": [{"lang": "en", "value": desc}],
                "affected": [{"vendor": "ExampleShop", "product": "example-shop"}],
                "problemTypes": [{"descriptions": [{"type": "CWE", "cweId": cwe, "lang": "en"}]}],
                "metrics": [{score_key: {"baseScore": score, "vectorString": "CVSS:X/AV:N"}}],
                "references": [{"url": "https://example.com/adv", "tags": ["vendor-advisory"]}],
            }
        },
    }


def test_parse_record_normalizes_fields():
    p = parse_record(_record())
    assert p["cve_id"] == "CVE-2099-7101"
    assert p["source"] == "cvelist"
    assert p["vendor"] == "ExampleShop" and p["product"] == "example-shop"
    assert p["cwe"] == ["CWE-89"]
    assert p["cvss_score"] == 9.8
    assert p["references"][0]["url"] == "https://example.com/adv"
    assert p["published"] == "2026-10-28T09:00:00Z"   # normalized to trailing Z
    assert p["modified"] == "2026-10-29T09:00:00Z"


def test_rejected_record_is_dropped():
    assert parse_record(_record(state="REJECTED")) is None


def test_missing_cve_id_is_dropped():
    raw = _record()
    raw["cveMetadata"].pop("cveId")
    assert parse_record(raw) is None


def test_cvss_prefers_v4_over_v3():
    raw = _record()
    raw["containers"]["cna"]["metrics"] = [
        {"cvssV3_1": {"baseScore": 7.0, "vectorString": "v3"}},
        {"cvssV4_0": {"baseScore": 9.3, "vectorString": "v4"}},
    ]
    p = parse_record(raw)
    assert p["cvss_score"] == 9.3 and p["cvss_vector"] == "v4"


def test_cwe_and_metrics_fall_back_to_adp_container():
    raw = _record(cwe="CWE-79")
    # Strip CWE/metrics from the CNA; put them in an ADP container (e.g. CISA-ADP).
    raw["containers"]["cna"]["problemTypes"] = []
    raw["containers"]["cna"]["metrics"] = []
    raw["containers"]["adp"] = [{
        "problemTypes": [{"descriptions": [{"cweId": "CWE-79"}]}],
        "metrics": [{"cvssV3_1": {"baseScore": 6.1, "vectorString": "adp"}}],
    }]
    p = parse_record(raw)
    assert p["cwe"] == ["CWE-79"]
    assert p["cvss_score"] == 6.1 and p["cvss_vector"] == "adp"


def test_webapp_filter_keeps_web_cwe_drops_hardware():
    web = parse_record(_record(cwe="CWE-89", desc="SQL injection"))
    hw = parse_record(_record(cve="CVE-2099-7102", cwe="CWE-121",
                              desc="Stack buffer overflow via serial console, physical access"))
    assert is_webapp_relevant(web) is True      # CWE-89 is a web CWE
    assert is_webapp_relevant(hw) is False       # CWE-121 + no appsec terms


def test_parse_records_filters_and_caps():
    raws = [
        _record(cve="CVE-2099-7101", cwe="CWE-89", desc="sql injection"),
        _record(cve="CVE-2099-7102", cwe="CWE-121", desc="physical overflow"),  # dropped (non-web)
        _record(cve="CVE-2099-7103", state="REJECTED"),                          # dropped (rejected)
        _record(cve="CVE-2099-7104", cwe="CWE-79", desc="stored xss"),
    ]
    kept = parse_records(raws, webapp_only=True)
    assert [r["cve_id"] for r in kept] == ["CVE-2099-7101", "CVE-2099-7104"]
    # cap applies after filtering
    assert [r["cve_id"] for r in parse_records(raws, webapp_only=True, cap=1)] == ["CVE-2099-7101"]
    # without the webapp filter the hardware CVE is kept (rejected still dropped)
    assert "CVE-2099-7102" in [r["cve_id"] for r in parse_records(raws, webapp_only=False)]


def _zip_of(members: dict[str, dict]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, obj in members.items():
            zf.writestr(name, json.dumps(obj))
    return buf.getvalue()


def test_records_from_zip_bytes_reads_json_members_only():
    blob = _zip_of({
        "cves/2099/7xxx/CVE-2099-7101.json": _record(cve="CVE-2099-7101", cwe="CWE-89"),
        "cves/2099/7xxx/CVE-2099-7102.json": _record(cve="CVE-2099-7102", cwe="CWE-121",
                                                     desc="physical overflow"),
        "delta.json": {"numberOfChanges": 2},          # manifest, not a CVE record
        "README.md": {"not": "json-but-skipped-by-ext"},
    })
    recs = records_from_zip_bytes(blob, webapp_only=True)
    assert [r["cve_id"] for r in recs] == ["CVE-2099-7101"]


def test_records_from_zip_skips_oversized_member():
    # A member whose declared uncompressed size exceeds the cap is skipped
    # (decompression-bomb guard), without failing the rest.
    big_desc = "sql injection " * 5000
    blob = _zip_of({
        "CVE-2099-7101.json": _record(cve="CVE-2099-7101", cwe="CWE-89", desc=big_desc),
        "CVE-2099-7104.json": _record(cve="CVE-2099-7104", cwe="CWE-79", desc="xss"),
    })
    recs = records_from_zip_bytes(blob, webapp_only=True, max_entry_bytes=1024)
    assert [r["cve_id"] for r in recs] == ["CVE-2099-7104"]


def test_bad_zip_returns_empty_not_an_error():
    assert records_from_zip_bytes(b"not a zip at all") == []


def test_apply_to_record_fills_gaps_without_clobbering():
    rec = CveRecord(cve_id="CVE-2099-7101", description="existing", cvss_score=7.0,
                    references=[{"url": "https://existing", "tags": ["x"]}])
    apply_to_record(rec, parse_record(_record()))
    assert rec.description == "existing"      # not clobbered
    assert rec.cvss_score == 7.0              # not clobbered
    assert rec.vendor == "ExampleShop"        # filled (was empty)
    assert rec.cwe == ["CWE-89"]              # filled
    urls = {r["url"] for r in rec.references}
    assert urls == {"https://existing", "https://example.com/adv"}  # unioned
