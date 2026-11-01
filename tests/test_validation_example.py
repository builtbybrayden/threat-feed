"""The local validation example must actually validate: the detection fires on
the vulnerable instance and stays silent on both controls. This guards the worked
example that decisions.yaml cites as `lab-validated` evidence."""

import importlib.util

from pipeline.util import ROOT

_RUNNER = ROOT / "validation" / "example_path_traversal" / "run_validation.py"


def _load_runner():
    spec = importlib.util.spec_from_file_location("tf_run_validation", _RUNNER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_example_detection_passes_all_three_controls():
    result = _load_runner().run()
    assert result["validated"] is True
    by_name = {c["name"]: c for c in result["controls"]}
    assert by_name["vulnerable_instance"]["detected"] is True
    assert by_name["patched_control"]["detected"] is False
    assert by_name["negative_control_benign"]["detected"] is False
