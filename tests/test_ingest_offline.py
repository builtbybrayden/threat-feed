"""End-to-end offline run: exercises scoring + triage + candidate + site output
against hand-built fixtures, with no network."""

import json

from pipeline.ingest import build_parser, run
from pipeline.util import ROOT


def _write(path, obj):
    path.write_text(json.dumps(obj), encoding="utf-8")


def _build_sample(sample_dir):
    sample_dir.mkdir(parents=True, exist_ok=True)
    # A research item mentioning a KEV, HTTP-detectable, uncovered CVE -> candidate.
    _write(sample_dir / "items.json", [
        {
            "id": "item1", "source": "PortSwigger Research", "source_type": "research",
            "title": "Confluence RCE CVE-2099-0001 exploited in the wild",
            "url": "https://example.com/a", "published": "2026-10-27T00:00:00Z",
            "summary": "A prompt injection and SSRF chain.", "cves": ["CVE-2099-0001"],
        },
        {
            "id": "item2", "source": "Simon Willison", "source_type": "news",
            "title": "Something already covered CVE-2099-0002",
            "url": "https://example.com/b", "published": "2026-10-27T00:00:00Z",
            "summary": "covered", "cves": ["CVE-2099-0002"],
        },
    ])
    _write(sample_dir / "kev.json", {"vulnerabilities": [
        {"cveID": "CVE-2099-0001", "vendorProject": "Atlassian", "product": "Confluence"},
    ]})
    _write(sample_dir / "epss.json", {"data": [
        {"cve": "CVE-2099-0001", "epss": "0.80"},
        {"cve": "CVE-2099-0002", "epss": "0.20"},
    ]})
    _write(sample_dir / "nvd.json", {
        "CVE-2099-0001": {
            "description": "RCE in Confluence.", "cwe": ["CWE-918"],
            "cvss_vector": "CVSS:3.1/AV:N/AC:L", "cvss_score": 9.8,
            "vendor": "atlassian", "product": "confluence",
            "cpes": ["cpe:2.3:a:atlassian:confluence:1.0:*:*:*:*:*:*:*"],
            "references": [{"url": "https://ex/adv", "tags": ["Exploit"]}],
        },
        "CVE-2099-0002": {
            "description": "Covered bug.", "cwe": ["CWE-79"],
            "cvss_vector": "CVSS:3.1/AV:N", "cvss_score": 6.1,
            "vendor": "x", "product": "y", "cpes": [], "references": [],
        },
    })
    _write(sample_dir / "poc.json", {"CVE-2099-0001": ["https://github.com/x/poc"]})
    # 0002 already has a template; 0001 does not -> only 0001 is a gap.
    _write(sample_dir / "coverage_index.json", {"CVE-2099-0002": "http/cves/CVE-2099-0002.yaml"})
    # CVE-List delta: one webapp CVE (kept), one hardware CVE (filtered out at
    # ingest), one REJECTED (dropped). Raw CVE 5.x shape, as the network path sees.
    _write(sample_dir / "cvelist.json", [
        {
            "cveMetadata": {"cveId": "CVE-2099-7101", "state": "PUBLISHED",
                            "datePublished": "2026-10-28T00:00:00Z", "dateUpdated": "2026-10-28T00:00:00Z"},
            "containers": {"cna": {
                "descriptions": [{"lang": "en", "value": "SQL injection over HTTP in example-shop."}],
                "affected": [{"vendor": "ExampleShop", "product": "example-shop"}],
                "problemTypes": [{"descriptions": [{"cweId": "CWE-89"}]}],
                "metrics": [{"cvssV3_1": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N"}}],
                "references": [{"url": "https://example.com/shop-sqli"}],
            }},
        },
        {
            "cveMetadata": {"cveId": "CVE-2099-7102", "state": "PUBLISHED",
                            "datePublished": "2026-10-28T00:00:00Z", "dateUpdated": "2026-10-28T00:00:00Z"},
            "containers": {"cna": {
                "descriptions": [{"lang": "en", "value": "Physical-access stack overflow in router firmware."}],
                "problemTypes": [{"descriptions": [{"cweId": "CWE-121"}]}],
            }},
        },
        {
            "cveMetadata": {"cveId": "CVE-2099-7103", "state": "REJECTED",
                            "datePublished": "2026-10-28T00:00:00Z", "dateUpdated": "2026-10-28T00:00:00Z"},
            "containers": {"cna": {}},
        },
    ])
    # OSV: a crates.io record whose own text/CWE would NOT classify as appsec, to
    # prove OSV records are treated as appsec (package vuln) via provenance, and a
    # CVE-less record that must be dropped. Low-signal on purpose so it is not a
    # candidate (keeps the candidate-count assertions above focused).
    _write(sample_dir / "osv.json", [
        {
            "id": "RUSTSEC-2099-0001", "aliases": ["CVE-2099-8001"],
            "summary": "Resource exhaustion in example-lib under heavy load.",
            "modified": "2026-10-29T00:00:00Z", "published": "2026-10-29T00:00:00Z",
            "affected": [{"package": {"name": "example-lib", "ecosystem": "crates.io"}}],
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H"}],
            "database_specific": {"cwe_ids": ["CWE-400"]},
            "references": [{"type": "ADVISORY", "url": "https://rustsec.org/advisories/RUSTSEC-2099-0001"}],
        },
        {
            "id": "RUSTSEC-2099-0002", "aliases": ["RUSTSEC-2099-0002"],   # no CVE -> dropped
            "summary": "Unmaintained crate.",
            "modified": "2026-10-29T00:00:00Z",
            "affected": [{"package": {"name": "example-dead", "ecosystem": "crates.io"}}],
        },
    ])
    # Validation results: a curated (vulhub, high-confidence) pass for the SQLi
    # candidate, and an inferred (docker-hub, low-confidence) pass for the OSV CVE.
    def _pass_controls():
        return [
            {"name": "vulnerable_instance", "expect": "detect", "detected": True, "pass": True},
            {"name": "patched_control", "expect": "no-detect", "detected": False, "pass": True},
            {"name": "negative_control_benign", "expect": "no-detect", "detected": False, "pass": True},
        ]
    vdir = sample_dir / "validations"
    (vdir / "CVE-2099-7101").mkdir(parents=True, exist_ok=True)
    _write(vdir / "CVE-2099-7101" / "result.json", {
        "cve_id": "CVE-2099-7101", "template": "http/cves/CVE-2099-7101.yaml",
        "controls": _pass_controls(), "runner": "nuclei", "generated": "2099-10-29T00:00:00Z",
        "lab": {"source": "vulhub", "confidence": "high",
                "vulnerable": {"image": "vulhub/example-shop:2.3.0", "version": "2.3.0"},
                "patched": {"image": "vulhub/example-shop:2.3.1", "version": "2.3.1"}},
    })
    (vdir / "CVE-2099-8001").mkdir(parents=True, exist_ok=True)
    _write(vdir / "CVE-2099-8001" / "result.json", {
        "cve_id": "CVE-2099-8001", "template": "http/cves/CVE-2099-8001.yaml",
        "controls": _pass_controls(), "runner": "nuclei", "generated": "2099-10-30T00:00:00Z",
        "lab": {"source": "docker-hub-inference", "confidence": "low",
                "vulnerable": {"image": "example-lib:1.4.2", "version": "1.4.2"},
                "patched": {"image": "example-lib:1.4.3", "version": "1.4.3"}},
    })


def test_offline_run_produces_site_and_one_candidate(tmp_path):
    sample = tmp_path / "sample_data"
    _build_sample(sample)
    args = build_parser().parse_args([
        "--offline",
        "--config", str(ROOT / "config.yaml"),
        "--watchlist", str(ROOT / "watchlist.yaml"),
        "--state", str(tmp_path / "state.json"),
        "--site", str(tmp_path / "site"),
        "--briefs", str(tmp_path / "briefs"),
        "--sample", str(sample),
    ])
    summary = run(args)

    data = json.loads((tmp_path / "site" / "data.json").read_text())
    cand = json.loads((tmp_path / "site" / "candidates.json").read_text())

    # Confluence item is KEV + high EPSS + watchlist + PoC -> scores near the top.
    top = data["items"][0]
    assert top["cves"] == ["CVE-2099-0001"]
    assert top["kev"] is True
    assert "KEV" in top["tags"] and "watchlist" in top["tags"]

    # Two open gaps now: the uncovered KEV CVE, and the uncovered HTTP-detectable
    # webapp SQLi that CVE-List surfaced (it matches the AppSec watchlist). The KEV
    # one scores higher, so it ranks first.
    ids = [c["cve_id"] for c in cand["candidates"]]
    assert ids == ["CVE-2099-0001", "CVE-2099-7101"]
    assert cand["candidates"][0]["cve_id"] == "CVE-2099-0001"
    assert cand["candidates"][0]["nuclei_template"] is None
    cvelist_cand = next(c for c in cand["candidates"] if c["cve_id"] == "CVE-2099-7101")
    assert cvelist_cand["origins"] == ["cvelist"]
    assert cvelist_cand["coverage"] == "gap"
    assert "watchlist product" in cvelist_cand["candidate_reasons"]

    # Stats reflect 1 KEV tracked, 0% covered, 2 gaps.
    assert summary["stats"]["kev_tracked"] == 1
    assert summary["stats"]["open_gaps"] == 2

    # The detection queue is user-curated (GitHub issues); offline there are none,
    # so it's written and empty — and no briefs are auto-generated.
    queue = json.loads((tmp_path / "site" / "queue.json").read_text())
    assert queue["queue"] == []
    assert summary["queue"] == 0

    # Coverage was known (the fixture index exists): 0001 is a confirmed gap, and
    # the coverage index is reported available with no unknowns.
    assert data["coverage_index"]["available"] is True
    assert data["stats"]["coverage_index_available"] is True
    assert data["stats"]["coverage_unknown"] == 0
    assert cand["candidates"][0]["coverage"] == "gap"
    assert "no existing Nuclei template" in cand["candidates"][0]["candidate_reasons"]

    # CVE-List intake: the webapp CVE (SQLi, CWE-89) is imported and reaches the
    # board; the hardware CVE (CWE-121, physical) and the REJECTED one are not.
    by_cve = {t["cve_id"]: t for t in data["threats"]}
    assert "CVE-2099-7101" in by_cve
    assert "CVE-2099-7102" not in by_cve      # filtered out: not webapp-relevant
    assert "CVE-2099-7103" not in by_cve      # dropped: REJECTED
    # Provenance is tracked per source, not collapsed to one origin. (The threat
    # card's existing "sources" = feed articles; "origins" = intake streams.)
    assert by_cve["CVE-2099-7101"]["origins"] == ["cvelist"]
    # CVE-2099-0001 was seen by a feed item, KEV, and NVD enrichment.
    assert set(by_cve["CVE-2099-0001"]["origins"]) == {"feed", "kev", "nvd"}

    # OSV intake: the crates.io record is keyed by its CVE alias and imported; the
    # CVE-less record is dropped. Though its own CWE-400/text would not classify as
    # appsec, it is marked appsec because an OSV package vuln inherently is.
    assert "CVE-2099-8001" in by_cve
    assert "CVE-2099-8002" not in by_cve           # no CVE alias -> dropped
    assert by_cve["CVE-2099-8001"]["origins"] == ["osv"]
    assert by_cve["CVE-2099-8001"]["appsec"] is True
    assert "rust" in by_cve["CVE-2099-8001"]["ecosystems"]
    # It carries no priority signal, so it is not a candidate (counts unchanged).
    assert "CVE-2099-8001" not in [c["cve_id"] for c in cand["candidates"]]

    # Validation artifacts (sample_data/validations/<CVE>/result.json) surface on
    # the records and in the headline stats. CVE-2099-7101 has a curated (vulhub)
    # pass; CVE-2099-8001 has an inferred (docker-hub) pass, flagged low-confidence.
    val_7101 = by_cve["CVE-2099-7101"]["validation"]
    assert val_7101 and val_7101["validated"] is True
    assert val_7101["source"] == "vulhub" and val_7101["confidence"] == "high"
    val_8001 = by_cve["CVE-2099-8001"]["validation"]
    assert val_8001 and val_8001["source"] == "docker-hub-inference"
    assert val_8001["confidence"] == "low" and val_8001["lab_note"]   # inferred => noted
    assert data["stats"]["validations"]["validated"] == 2
    assert data["stats"]["validations"]["validated_inferred_lab"] == 1


def test_offline_run_without_coverage_index_reports_unknown(tmp_path):
    # When no coverage index is available, coverage must be *unknown*, not a
    # confirmed gap: the pipeline must not claim an absent template it never checked.
    sample = tmp_path / "sample_data"
    _build_sample(sample)
    (sample / "coverage_index.json").unlink()  # no index this run

    args = build_parser().parse_args([
        "--offline",
        "--config", str(ROOT / "config.yaml"),
        "--watchlist", str(ROOT / "watchlist.yaml"),
        "--state", str(tmp_path / "state.json"),
        "--site", str(tmp_path / "site"),
        "--briefs", str(tmp_path / "briefs"),
        "--sample", str(sample),
    ])
    run(args)

    data = json.loads((tmp_path / "site" / "data.json").read_text())
    cand = json.loads((tmp_path / "site" / "candidates.json").read_text())

    assert data["coverage_index"]["available"] is False
    assert data["stats"]["coverage_index_available"] is False
    assert data["stats"]["coverage_unknown"] == data["stats"]["total_cves"]
    # Coverage % is computed only over known records, so it's not a false "0% covered".
    assert data["stats"]["kev_coverage_known"] == 0
    # Every threat is unknown, not "gap".
    assert all(t["coverage"] == "unknown" for t in data["threats"])
    # A candidate under unknown coverage is provisional.
    assert cand["candidates"], "expected provisional candidates under unknown coverage"
    assert all(
        any("not ruled out" in r for r in c["candidate_reasons"])
        for c in cand["candidates"]
    )
