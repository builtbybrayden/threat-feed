from pipeline.models import CveRecord, Detection, Item
from pipeline.state import State


def _item(id="a"):
    return Item(
        id=id, source="S", source_type="news", title="t",
        url="https://e.com", published="2026-10-27T00:00:00Z", summary="s",
    )


def test_upsert_item_dedupes():
    st = State()
    assert st.upsert_item(_item("a")) is True   # new
    assert st.upsert_item(_item("a")) is False  # duplicate id
    assert len(st.items) == 1


def test_get_cve_creates_once():
    st = State()
    r1 = st.get_cve("cve-2024-1")
    r2 = st.get_cve("CVE-2024-1")  # case-insensitive, same record
    assert r1 is r2
    assert r1.cve_id == "CVE-2024-1"
    assert r1.first_seen is not None


def test_save_load_round_trip(tmp_path):
    st = State()
    st.upsert_item(_item("a"))
    rec = st.get_cve("CVE-2024-1")
    rec.kev = True
    rec.detection = Detection(remote_network=True, likely_http=True)
    rec.nuclei_template = "http/x.yaml"
    path = tmp_path / "state.json"
    st.save(path)

    loaded = State.load(path)
    assert "a" in loaded.items
    back = loaded.cves["CVE-2024-1"]
    assert isinstance(back, CveRecord)
    assert back.kev is True
    assert back.detection.likely_http is True
    assert back.nuclei_template == "http/x.yaml"


def test_load_missing_file_is_empty(tmp_path):
    st = State.load(tmp_path / "nope.json")
    assert st.items == {} and st.cves == {}
