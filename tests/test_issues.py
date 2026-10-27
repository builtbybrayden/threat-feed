from pipeline.issues import labels_for, sync_candidates
from pipeline.models import CveRecord, Detection


class FakeClient:
    """In-memory GitHub stand-in so idempotency is tested without the network."""

    def __init__(self, preexisting=None):
        self.preexisting = preexisting or {}   # cve_id -> number (simulates lost state)
        self.created = []
        self.comments = []
        self.closed = []
        self._next = 100

    def find_issue_number(self, cve_id):
        return self.preexisting.get(cve_id.upper())

    def create_issue(self, title, body, labels):
        self._next += 1
        self.created.append((title, labels))
        return self._next

    def comment(self, number, body):
        self.comments.append((number, body))

    def close(self, number):
        self.closed.append(number)


def _cand(cve_id, **kw):
    rec = CveRecord(cve_id=cve_id, detection=Detection(remote_network=True, likely_http=True), **kw)
    return rec


def test_creates_one_issue_per_new_candidate():
    recs = [_cand("CVE-2024-1", kev=True), _cand("CVE-2024-2")]
    client = FakeClient()
    summary = sync_candidates(recs, {r.cve_id: r for r in recs}, client)
    assert len(client.created) == 2
    assert summary["created"] == ["CVE-2024-1", "CVE-2024-2"]
    assert all(r.issue_number is not None for r in recs)


def test_rerun_is_idempotent_no_duplicates():
    rec = _cand("CVE-2024-1", kev=True)
    allrecs = {rec.cve_id: rec}
    client = FakeClient()
    sync_candidates([rec], allrecs, client)
    first = rec.issue_number
    # Second run: issue_number is already set -> must not create again.
    sync_candidates([rec], allrecs, client)
    assert len(client.created) == 1
    assert rec.issue_number == first


def test_adopts_existing_issue_when_state_is_lost():
    rec = _cand("CVE-2024-9", kev=True)  # issue_number is None (lost state)
    client = FakeClient(preexisting={"CVE-2024-9": 42})
    sync_candidates([rec], {rec.cve_id: rec}, client)
    assert client.created == []        # found via marker search -> no duplicate
    assert rec.issue_number == 42


def test_closes_issue_when_template_appears_upstream():
    rec = _cand("CVE-2024-1", kev=True)
    rec.issue_number = 7
    rec.nuclei_template = "http/cves/2024/CVE-2024-1.yaml"
    client = FakeClient()
    summary = sync_candidates([], {rec.cve_id: rec}, client)
    assert summary["closed"] == ["CVE-2024-1"]
    assert client.closed == [7] and client.comments
    assert rec.issue_number is None


def test_labels_reflect_signals():
    rec = _cand("CVE-2024-1", kev=True)
    rec.detection.has_poc = True
    rec.detection.suggested_template_type = "behavioral"
    labels = labels_for(rec)
    assert "nuclei-candidate" in labels
    assert "kev" in labels
    assert "has-poc" in labels
    assert "behavioral" in labels
