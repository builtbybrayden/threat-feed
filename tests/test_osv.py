import io
import json
import zipfile

from pipeline.models import CveRecord
from pipeline.osv import (
    apply_to_record,
    parse_record,
    parse_records,
    records_from_zip_bytes,
)


def _osv(id="RUSTSEC-2099-0001", cve="CVE-2099-8001", eco="crates.io", cwe="CWE-918",
         modified="2026-10-29T12:00:00Z", withdrawn=None, aliases=None):
    rec = {
        "id": id,
        "aliases": aliases if aliases is not None else [cve, "GHSA-demo"],
        "summary": "SSRF in example-http",
        "modified": modified,
        "published": "2026-10-29T10:00:00Z",
        "affected": [{"package": {"name": "example-http", "ecosystem": eco}}],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
        "database_specific": {"cwe_ids": [cwe]},
        "references": [{"type": "ADVISORY", "url": "https://rustsec.org/advisories/RUSTSEC-2099-0001"}],
    }
    if withdrawn:
        rec["withdrawn"] = withdrawn
    return rec


def test_parse_record_normalizes_and_keys_by_cve_alias():
    p = parse_record(_osv())
    assert p["cve_id"] == "CVE-2099-8001"          # pulled from aliases, uppercased
    assert p["source"] == "osv"
    assert p["osv_id"] == "RUSTSEC-2099-0001"
    assert p["ecosystems"] == ["rust"]              # crates.io -> rust
    assert p["product"] == "example-http"
    assert p["cvss_vector"].startswith("CVSS:3.1/AV:N")
    assert p["cwe"] == ["CWE-918"]
    assert p["modified"] == "2026-10-29T12:00:00Z"
    assert p["references"][0]["url"].endswith("RUSTSEC-2099-0001")


def test_record_without_cve_alias_is_dropped():
    assert parse_record(_osv(aliases=["RUSTSEC-2099-0003", "GHSA-x"])) is None


def test_withdrawn_record_is_dropped():
    assert parse_record(_osv(withdrawn="2026-10-31T00:00:00Z")) is None


def test_cvss_prefers_v4_vector():
    raw = _osv()
    raw["severity"] = [
        {"type": "CVSS_V3", "score": "CVSS:3.1/v3"},
        {"type": "CVSS_V4", "score": "CVSS:4.0/v4"},
    ]
    assert parse_record(raw)["cvss_vector"] == "CVSS:4.0/v4"


def test_go_and_unknown_ecosystem_mapping():
    assert parse_record(_osv(cve="CVE-2099-8002", eco="Go"))["ecosystems"] == ["go"]
    # An unknown ecosystem is kept, lower-cased, rather than dropped.
    assert parse_record(_osv(cve="CVE-2099-8003", eco="SwiftURL"))["ecosystems"] == ["swifturl"]


def test_parse_records_filters_by_since_and_caps():
    raws = [
        _osv(cve="CVE-2099-8001", modified="2026-10-29T00:00:00Z"),
        _osv(cve="CVE-2099-8002", modified="2026-01-01T00:00:00Z"),   # too old
        _osv(cve="CVE-2099-8003", modified="2026-10-30T00:00:00Z"),
    ]
    kept = parse_records(raws, since="2026-10-01T00:00:00Z")
    assert [r["cve_id"] for r in kept] == ["CVE-2099-8001", "CVE-2099-8003"]
    assert [r["cve_id"] for r in parse_records(raws, since="2026-10-01T00:00:00Z", cap=1)] == ["CVE-2099-8001"]


def _zip_of(members: dict[str, dict]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, obj in members.items():
            zf.writestr(name, json.dumps(obj))
    return buf.getvalue()


def test_records_from_zip_bytes_reads_and_filters():
    blob = _zip_of({
        "RUSTSEC-2099-0001.json": _osv(cve="CVE-2099-8001", modified="2026-10-29T00:00:00Z"),
        "RUSTSEC-2099-0003.json": _osv(aliases=["RUSTSEC-2099-0003"]),        # no CVE -> dropped
        "RUSTSEC-2099-0009.json": _osv(cve="CVE-2099-8009", modified="2020-01-01T00:00:00Z"),  # old
    })
    recs = records_from_zip_bytes(blob, since="2026-10-01T00:00:00Z")
    assert [r["cve_id"] for r in recs] == ["CVE-2099-8001"]


def test_bad_zip_returns_empty():
    assert records_from_zip_bytes(b"not a zip") == []


def test_apply_to_record_fills_without_clobbering_and_unions():
    rec = CveRecord(cve_id="CVE-2099-8001", description="existing", ecosystems=["web"],
                    references=[{"url": "https://existing", "tags": ["x"]}])
    apply_to_record(rec, parse_record(_osv()))
    assert rec.description == "existing"                      # not clobbered
    assert set(rec.ecosystems) == {"web", "rust"}             # unioned
    assert rec.cvss_vector.startswith("CVSS:3.1/AV:N")        # filled (was empty)
    assert rec.cwe == ["CWE-918"]
    assert {r["url"] for r in rec.references} == {"https://existing", "https://rustsec.org/advisories/RUSTSEC-2099-0001"}
