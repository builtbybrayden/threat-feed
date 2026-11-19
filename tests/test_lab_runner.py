"""The generalized Nuclei lab runner: pure result assembly (no binary), plus a
real nuclei run against the local path-traversal lab when nuclei is installed."""

import importlib.util
import shutil
import threading

import pytest

from pipeline.util import ROOT

_LAB_RUNNER = ROOT / "validation" / "lab_runner.py"
_LABAPP = ROOT / "validation" / "example_path_traversal" / "labapp.py"
_TEMPLATE = ROOT / "validation" / "example_path_traversal" / "detection.yaml"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


lab_runner = _load("tf_lab_runner", _LAB_RUNNER)


# -- pure assembly (no nuclei) ------------------------------------------------
def test_all_three_detected_as_expected_is_validated():
    r = lab_runner.build_result("CVE-2099-0001", "t.yaml",
                                {"vulnerable_instance": True, "patched_control": False,
                                 "negative_control_benign": False})
    assert r["validated"] is True
    assert {c["name"]: c["pass"] for c in r["controls"]} == {
        "vulnerable_instance": True, "patched_control": True, "negative_control_benign": True}


def test_patched_fires_is_not_validated():
    r = lab_runner.build_result("CVE-2099-0001", "t.yaml",
                                {"vulnerable_instance": True, "patched_control": True,
                                 "negative_control_benign": False})
    assert r["validated"] is False


def test_missing_benign_control_is_not_validated():
    r = lab_runner.build_result("CVE-2099-0001", "t.yaml",
                                {"vulnerable_instance": True, "patched_control": False})
    assert r["validated"] is False           # benign control never ran


def test_lab_provenance_passes_through():
    lab = {"source": "docker-hub-inference", "confidence": "low",
           "vulnerable": {"image": "x:1.0", "version": "1.0"}}
    r = lab_runner.build_result("CVE-2099-0001", "t.yaml",
                                {"vulnerable_instance": True, "patched_control": False,
                                 "negative_control_benign": False}, lab=lab)
    assert r["lab"]["source"] == "docker-hub-inference"
    assert r["cve_id"] == "CVE-2099-0001" and r["runner"] == "nuclei"


# -- real nuclei run against the lab (skipped if nuclei absent) ---------------
@pytest.mark.skipif(shutil.which("nuclei") is None, reason="nuclei binary not installed")
def test_nuclei_detects_vulnerable_not_patched(tmp_path):
    labapp = _load("tf_labapp2", _LABAPP)
    base = str(tmp_path)
    labapp.build_root(base)
    vuln = labapp.make_server("vulnerable", base, port=0)
    patched = labapp.make_server("patched", base, port=0)
    threading.Thread(target=vuln.serve_forever, daemon=True).start()
    threading.Thread(target=patched.serve_forever, daemon=True).start()
    try:
        vuln_url = f"http://127.0.0.1:{vuln.server_address[1]}"
        patched_url = f"http://127.0.0.1:{patched.server_address[1]}"
        assert lab_runner.run_nuclei(str(_TEMPLATE), vuln_url) is True
        assert lab_runner.run_nuclei(str(_TEMPLATE), patched_url) is False
    finally:
        vuln.shutdown()
        patched.shutdown()
