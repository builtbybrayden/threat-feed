from pipeline.advisories import apply_to_record, parse_advisories, parse_advisory
from pipeline.models import CveRecord

RAW = {
    "ghsa_id": "GHSA-xxxx",
    "cve_id": "cve-2099-1234",
    "summary": "SSRF in example-lib",
    "severity": "critical",
    "published_at": "2026-10-20T00:00:00Z",
    "html_url": "https://github.com/advisories/GHSA-xxxx",
    "cvss_severities": {
        "cvss_v3": {"score": 9.1, "vector_string": "CVSS:3.1/AV:N"},
        "cvss_v4": {"score": 9.8, "vector_string": "CVSS:4.0/AV:N"},
    },
    "epss": {"percentage": 0.42, "percentile": 0.97},
    "cwes": [{"cwe_id": "CWE-918", "name": "SSRF"}],
    "references": ["https://example.com/adv"],
    "identifiers": [{"type": "CVE", "value": "CVE-2099-1234"}],
    "vulnerabilities": [{"package": {"ecosystem": "pip", "name": "example-lib"}}],
}


def test_parse_advisory_normalizes_and_maps_ecosystem():
    p = parse_advisory(RAW)
    assert p["cve_id"] == "CVE-2099-1234"          # uppercased
    assert p["ecosystems"] == ["pypi"]              # pip -> pypi
    assert p["product"] == "example-lib"
    assert p["cvss_score"] == 9.8                   # prefers CVSS v4
    assert p["epss"] == 0.42
    assert p["cwe"] == ["CWE-918"]
    assert p["ghsa_id"] == "GHSA-xxxx"
    assert any(r["url"] == "https://github.com/advisories/GHSA-xxxx" for r in p["references"])


def test_cve_pulled_from_identifiers_when_cve_id_absent():
    raw = dict(RAW)
    raw.pop("cve_id")
    assert parse_advisory(raw)["cve_id"] == "CVE-2099-1234"


def test_advisory_without_cve_is_skipped():
    raw = {"ghsa_id": "GHSA-nocve", "identifiers": [{"type": "GHSA", "value": "GHSA-nocve"}],
           "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "x"}}]}
    assert parse_advisory(raw) is None
    assert parse_advisories([raw, RAW]) == [parse_advisory(RAW)]


def test_apply_to_record_unions_ecosystems_without_clobbering():
    rec = CveRecord(cve_id="CVE-2099-1234", ecosystems=["web"], cvss_score=7.0)
    apply_to_record(rec, parse_advisory(RAW))
    # Existing CVSS is kept; ecosystem is a union, not a replace.
    assert rec.cvss_score == 7.0
    assert set(rec.ecosystems) == {"web", "pypi"}
    assert rec.ghsa_id == "GHSA-xxxx"
    assert rec.epss == 0.42
    assert rec.advisory_url == "https://github.com/advisories/GHSA-xxxx"
