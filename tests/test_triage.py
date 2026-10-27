from pipeline.models import CveRecord
from pipeline.triage import classify, evaluate_candidate


def _rec(**kw):
    return CveRecord(cve_id="CVE-2024-1234", **kw)


def test_classify_remote_http_and_behavioral(config):
    rec = _rec(
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cwe=["CWE-918"],  # SSRF, a web CWE
        poc_links=["https://github.com/x/poc"],
    )
    det = classify(rec, config)
    assert det.remote_network is True
    assert det.likely_http is True
    assert det.has_poc is True
    assert det.suggested_template_type == "behavioral"  # http + poc


def test_classify_defaults_to_fingerprint_without_signal(config):
    rec = _rec(cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", cwe=["CWE-200"])
    det = classify(rec, config)
    assert det.suggested_template_type == "version-fingerprint"


def test_candidate_requires_no_template_detectable_and_priority(config):
    rec = _rec(cvss_vector="CVSS:3.1/AV:N", cwe=["CWE-89"], kev=True)
    classify(rec, config)
    is_cand, reasons = evaluate_candidate(rec, config, watchlist_hit=False)
    assert is_cand is True
    assert "no existing Nuclei template" in reasons


def test_existing_template_is_not_a_candidate(config):
    rec = _rec(cvss_vector="CVSS:3.1/AV:N", cwe=["CWE-89"], kev=True,
               nuclei_template="http/cves/2024/CVE-2024-1234.yaml")
    classify(rec, config)
    is_cand, reasons = evaluate_candidate(rec, config, watchlist_hit=False)
    assert is_cand is False
    assert any("template already exists" in r for r in reasons)


def test_not_detectable_is_not_a_candidate(config):
    # Local-only (AV:L), non-web CWE -> not detectable even though it's KEV.
    rec = _rec(cvss_vector="CVSS:3.1/AV:L/AC:L", cwe=["CWE-787"], kev=True)
    classify(rec, config)
    is_cand, _ = evaluate_candidate(rec, config, watchlist_hit=False)
    assert is_cand is False


def test_priority_can_come_from_watchlist(config):
    rec = _rec(cvss_vector="CVSS:3.1/AV:N", cwe=["CWE-79"])  # not KEV, no epss
    classify(rec, config)
    assert evaluate_candidate(rec, config, watchlist_hit=True)[0] is True
    assert evaluate_candidate(rec, config, watchlist_hit=False)[0] is False
