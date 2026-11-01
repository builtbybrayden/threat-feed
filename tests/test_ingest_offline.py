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
