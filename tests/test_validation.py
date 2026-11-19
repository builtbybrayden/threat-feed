"""Validation-artifact loading: the 3-control gate, lab provenance, and the
tolerant loader. Pure; no Docker, no network."""

import json

import pytest

from pipeline import validation as V


def _result(**kw):
    base = {
        "cve_id": "CVE-2099-0001",
        "template": "http/cves/CVE-2099-0001.yaml",
        "controls": [
            {"name": "vulnerable_instance", "expect": "detect", "detected": True, "pass": True},
            {"name": "patched_control", "expect": "no-detect", "detected": False, "pass": True},
            {"name": "negative_control_benign", "expect": "no-detect", "detected": False, "pass": True},
        ],
        "lab": {"source": "vulhub", "confidence": "high"},
        "runner": "nuclei",
        "generated": "2099-10-29T00:00:00Z",
    }
    base.update(kw)
    return base


def test_all_controls_pass_is_validated():
    cve, rec = V.normalize(_result())
    assert cve == "CVE-2099-0001"
    assert rec["validated"] is True
    assert rec["missing_controls"] == []
    assert rec["lab"]["confidence"] == "high"


def test_pass_is_recomputed_not_trusted():
    # A file claims the vulnerable control passed, but it did not fire. The
    # loader must recompute pass from expect+detected and fail it.
    r = _result()
    r["controls"][0] = {"name": "vulnerable_instance", "expect": "detect", "detected": False, "pass": True}
    _, rec = V.normalize(r)
    assert rec["controls"][0]["pass"] is False
    assert rec["validated"] is False


def test_patched_false_positive_fails():
    r = _result()
    r["controls"][1] = {"name": "patched_control", "expect": "no-detect", "detected": True, "pass": True}
    _, rec = V.normalize(r)
    assert rec["controls"][1]["pass"] is False
    assert rec["validated"] is False


def test_missing_control_blocks_validated():
    # Only the vulnerable control present: can't be validated without the
    # patched + benign negatives, even though the one present passes.
    r = _result(controls=[{"name": "vulnerable_instance", "expect": "detect", "detected": True, "pass": True}])
    _, rec = V.normalize(r)
    assert set(rec["missing_controls"]) == {"patched_control", "negative_control_benign"}
    assert rec["validated"] is False


def test_inference_lab_gets_a_note_even_if_omitted():
    r = _result(lab={"source": "docker-hub-inference", "confidence": "low"})
    _, rec = V.normalize(r)
    assert rec["lab"]["source"] == "docker-hub-inference"
    assert rec["lab"]["note"]                       # synthesized
    assert "not a curated lab" in rec["lab"]["note"] or "supposed" in rec["lab"]["note"]


def test_bad_lab_source_is_an_error():
    with pytest.raises(ValueError):
        V.normalize(_result(lab={"source": "totally-made-up"}))


def test_missing_cve_is_an_error():
    with pytest.raises(ValueError):
        V.normalize(_result(cve_id="not-a-cve"))


def test_load_dir_nested_and_flat(tmp_path):
    root = tmp_path / "validations"
    # nested <CVE>/result.json
    d = root / "CVE-2099-0001"
    d.mkdir(parents=True)
    (d / "result.json").write_text(json.dumps(_result()), encoding="utf-8")
    # flat <CVE>.json
    (root / "CVE-2099-0002.json").write_text(
        json.dumps(_result(cve_id="CVE-2099-0002", lab={"source": "docker-hub-inference", "confidence": "low"})),
        encoding="utf-8",
    )
    vals, errors = V.load_validations(root)
    assert errors == []
    assert set(vals) == {"CVE-2099-0001", "CVE-2099-0002"}
    assert vals["CVE-2099-0002"]["lab"]["source"] == "docker-hub-inference"


def test_load_missing_dir_is_empty_not_error(tmp_path):
    vals, errors = V.load_validations(tmp_path / "nope")
    assert vals == {} and errors == []


def test_load_collects_bad_file_without_crashing(tmp_path):
    root = tmp_path / "validations"
    (root / "CVE-2099-0003").mkdir(parents=True)
    (root / "CVE-2099-0003" / "result.json").write_text("{ not json", encoding="utf-8")
    (root / "CVE-2099-0004.json").write_text(json.dumps(_result(cve_id="CVE-2099-0004")), encoding="utf-8")
    vals, errors = V.load_validations(root)
    assert "CVE-2099-0004" in vals            # the good one still loads
    assert len(errors) == 1                   # the bad one is reported, not fatal


def test_newest_generated_wins(tmp_path):
    root = tmp_path / "validations"
    (root / "CVE-2099-0005").mkdir(parents=True)
    (root / "CVE-2099-0005" / "result.json").write_text(
        json.dumps(_result(cve_id="CVE-2099-0005", generated="2099-01-01T00:00:00Z")), encoding="utf-8")
    (root / "CVE-2099-0005.json").write_text(
        json.dumps(_result(cve_id="CVE-2099-0005", generated="2099-12-31T00:00:00Z",
                           lab={"source": "custom", "confidence": "low"})), encoding="utf-8")
    vals, _ = V.load_validations(root)
    assert vals["CVE-2099-0005"]["lab"]["source"] == "custom"   # the newer file


def test_summarize_counts_outcomes():
    vals = {
        "CVE-2099-0001": V.normalize(_result())[1],
        "CVE-2099-0002": V.normalize(_result(cve_id="CVE-2099-0002", lab={"source": "docker-hub-inference", "confidence": "low"}))[1],
        "CVE-2099-0003": V.normalize(_result(cve_id="CVE-2099-0003",
                                             controls=[{"name": "vulnerable_instance", "expect": "detect", "detected": False, "pass": False},
                                                       {"name": "patched_control", "expect": "no-detect", "detected": False, "pass": True},
                                                       {"name": "negative_control_benign", "expect": "no-detect", "detected": False, "pass": True}]))[1],
    }
    s = V.summarize(vals)
    assert s["validated"] == 2
    assert s["validation_failed"] == 1
    assert s["validated_high_confidence"] == 1       # only the vulhub one
    assert s["validated_inferred_lab"] == 1          # the docker-hub-inference one


def test_view_is_compact_and_flags_source():
    _, rec = V.normalize(_result(lab={"source": "docker-hub-inference", "confidence": "low"}))
    v = V.view(rec)
    assert v["validated"] is True
    assert v["source"] == "docker-hub-inference" and v["confidence"] == "low"
    assert v["lab_note"]
    assert all(set(c) == {"name", "pass", "detected"} for c in v["controls"])
    assert V.view(None) is None
