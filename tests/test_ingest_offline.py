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

    # Exactly one open gap: the uncovered, detectable, KEV CVE.
    ids = [c["cve_id"] for c in cand["candidates"]]
    assert ids == ["CVE-2099-0001"]
    assert cand["candidates"][0]["nuclei_template"] is None

    # Stats reflect 1 KEV tracked, 0% covered, 1 gap.
    assert summary["stats"]["kev_tracked"] == 1
    assert summary["stats"]["open_gaps"] == 1

    # A brief was written for the candidate.
    assert (tmp_path / "briefs" / "CVE-2099-0001.md").exists()
