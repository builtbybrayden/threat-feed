import json

from pipeline.decisions import LIFECYCLE_STATES, load_decisions, summarize

VALID = """
- cve: CVE-2099-0999
  status: lab-validated
  reviewer: A. Analyst
  date: 2026-11-01
  rationale: HTTP traversal, PoC exists.
  template: validation/example_path_traversal/detection.yaml
  artifacts:
    - validation/example_path_traversal/result.json
  outcome: Detected on vuln, clean on patched + negative control.
- cve: CVE-2099-0002
  status: rejected
  reviewer: A. Analyst
  date: 2026-11-01
  rationale: Local-only; no safe remote check.
"""


def test_missing_file_is_empty_not_an_error(tmp_path):
    decisions, errors = load_decisions(tmp_path / "nope.yaml")
    assert decisions == {}
    assert errors == []


def test_load_valid_records(tmp_path):
    p = tmp_path / "decisions.yaml"
    p.write_text(VALID, encoding="utf-8")
    decisions, errors = load_decisions(p)
    assert errors == []
    assert set(decisions) == {"CVE-2099-0999", "CVE-2099-0002"}
    d = decisions["CVE-2099-0999"]
    assert d["status"] == "lab-validated"
    assert d["terminal"] is False
    assert d["artifacts"] == ["validation/example_path_traversal/result.json"]
    # "rejected" is a real terminal outcome, not a success.
    assert decisions["CVE-2099-0002"]["terminal"] is True


def test_invalid_status_is_reported_and_skipped(tmp_path):
    p = tmp_path / "decisions.yaml"
    p.write_text(
        "- cve: CVE-2099-0001\n  status: shipped-it\n"       # not a lifecycle state
        "- cve: CVE-2099-0002\n  status: reviewed\n",
        encoding="utf-8",
    )
    decisions, errors = load_decisions(p)
    assert "CVE-2099-0002" in decisions          # the good record survives
    assert "CVE-2099-0001" not in decisions      # the bad one is skipped
    assert any("shipped-it" in e for e in errors)


def test_bad_cve_and_unknown_field_are_errors(tmp_path):
    p = tmp_path / "decisions.yaml"
    p.write_text(
        "- cve: not-a-cve\n  status: reviewed\n"
        "- cve: CVE-2099-0003\n  status: reviewed\n  bogus: 1\n",
        encoding="utf-8",
    )
    decisions, errors = load_decisions(p)
    assert decisions == {}
    assert len(errors) == 2


def test_summarize_counts_every_state(tmp_path):
    p = tmp_path / "decisions.yaml"
    p.write_text(VALID, encoding="utf-8")
    decisions, _ = load_decisions(p)
    counts = summarize(decisions)
    assert set(counts) == set(LIFECYCLE_STATES)
    assert counts["lab-validated"] == 1
    assert counts["rejected"] == 1
    assert counts["candidate"] == 0


def test_date_is_coerced_to_json_serializable_string(tmp_path):
    # YAML would parse an unquoted ISO date as datetime.date, which breaks the
    # JSON site output; the loader must coerce it to a string.
    p = tmp_path / "decisions.yaml"
    p.write_text("- cve: CVE-2099-0001\n  status: reviewed\n  date: 2026-11-01\n", encoding="utf-8")
    decisions, _ = load_decisions(p)
    assert decisions["CVE-2099-0001"]["date"] == "2026-11-01"
    json.dumps(decisions)  # must not raise


def test_shipped_decisions_file_loads_cleanly():
    # The committed decisions.yaml must always be valid and serializable.
    from pipeline.util import ROOT
    decisions, errors = load_decisions(ROOT / "decisions.yaml")
    assert errors == []
    assert "CVE-2099-0999" in decisions
    json.dumps(decisions)
