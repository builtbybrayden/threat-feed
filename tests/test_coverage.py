from pipeline.coverage import build_index, load_index, save_index

TEMPLATE_WITH_CLASSIFICATION = """
id: CVE-2024-9999-detect
info:
  name: Example
  classification:
    cve-id: CVE-2024-9999
"""

TEMPLATE_FILENAME_ONLY = """
id: some-generic-check
info:
  name: Generic
"""

BROKEN_YAML = "id: [unclosed\n  info: :::"


def test_build_index_from_classification_and_filename(tmp_path):
    (tmp_path / "http").mkdir()
    (tmp_path / "http" / "cve-2024-9999.yaml").write_text(TEMPLATE_WITH_CLASSIFICATION)
    # Filename carries the CVE even when the body doesn't.
    (tmp_path / "http" / "CVE-2020-1111.yaml").write_text(TEMPLATE_FILENAME_ONLY)
    (tmp_path / "broken.yaml").write_text(BROKEN_YAML)  # must not crash

    index = build_index(tmp_path)
    assert index["CVE-2024-9999"] == "http/cve-2024-9999.yaml"
    assert index["CVE-2020-1111"] == "http/CVE-2020-1111.yaml"


def test_index_round_trip(tmp_path):
    out = tmp_path / "idx.json"
    save_index({"CVE-2024-9999": "http/x.yaml"}, out)
    loaded = load_index(out)
    assert loaded == {"CVE-2024-9999": "http/x.yaml"}
    assert load_index(tmp_path / "missing.json") == {}
