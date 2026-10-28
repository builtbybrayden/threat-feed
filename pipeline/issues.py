"""GitHub Issues work-queue: one idempotent issue per template candidate.

Idempotency is guaranteed two ways (CLAUDE.md: never open a duplicate):
  1. state records cve -> issue_number, so a known CVE is never re-opened;
  2. each issue body carries a hidden marker `<!-- threat-feed:CVE-... -->`,
     so even with lost state we can find an existing issue by search.

When a template later appears upstream for a CVE that has an open issue, we
comment with the template path and close the issue.

The network client is injected (GitHubClient for real use, a fake in tests),
so the sync logic itself is tested without hitting GitHub.
"""

from __future__ import annotations

from typing import Any, Optional, Protocol

from .briefs import render_markdown
from .models import CveRecord

CANDIDATE_LABEL = "nuclei-candidate"


def marker(cve_id: str) -> str:
    return f"<!-- threat-feed:{cve_id.upper()} -->"


def labels_for(rec: CveRecord) -> list[str]:
    labels = [CANDIDATE_LABEL]
    if rec.kev:
        labels.append("kev")
    if rec.detection.has_poc:
        labels.append("has-poc")
    labels.append(
        "behavioral" if rec.detection.suggested_template_type == "behavioral" else "fingerprint"
    )
    return labels


def issue_title(rec: CveRecord) -> str:
    product = f" ({rec.vendor}/{rec.product})" if rec.product else ""
    return f"[nuclei-candidate] {rec.cve_id}{product}"


def issue_body(rec: CveRecord) -> str:
    return f"{marker(rec.cve_id)}\n\n{render_markdown(rec)}"


class GitHubClient(Protocol):
    """Minimal surface the sync logic needs; satisfied by the real client + fakes."""

    def find_issue_number(self, cve_id: str) -> Optional[int]: ...
    def create_issue(self, title: str, body: str, labels: list[str]) -> int: ...
    def comment(self, number: int, body: str) -> None: ...
    def close(self, number: int) -> None: ...


def sync_candidates(
    candidates: list[CveRecord],
    all_records: dict[str, CveRecord],
    client: GitHubClient,
) -> dict[str, Any]:
    """Create/close issues idempotently. Mutates rec.issue_number in place.

    Returns a small summary dict for logging.
    """
    created, closed, skipped = [], [], []

    # 1. Open an issue for every candidate that doesn't already have one.
    for rec in candidates:
        if rec.issue_number is not None:
            skipped.append(rec.cve_id)
            continue
        existing = client.find_issue_number(rec.cve_id)
        if existing is not None:
            rec.issue_number = existing
            skipped.append(rec.cve_id)
            continue
        number = client.create_issue(issue_title(rec), issue_body(rec), labels_for(rec))
        rec.issue_number = number
        created.append(rec.cve_id)

    # 2. Close issues whose CVE has since gained upstream template coverage.
    for rec in all_records.values():
        if rec.issue_number is not None and rec.nuclei_template is not None:
            client.comment(
                rec.issue_number,
                f"Upstream Nuclei template now exists: `{rec.nuclei_template}`. "
                "Closing this candidate.",
            )
            client.close(rec.issue_number)
            closed.append(rec.cve_id)
            rec.issue_number = None

    return {"created": created, "closed": closed, "skipped": skipped}


# ---------------------------------------------------------------------------
# Real GitHub REST client (used only in CI, where a token is present).
# ---------------------------------------------------------------------------
class RestGitHubClient:
    def __init__(self, repo: str, token: str, session: Any, timeout: int = 20) -> None:
        self.repo = repo            # "owner/name"
        self.session = session
        self.timeout = timeout
        self.base = f"https://api.github.com/repos/{repo}"
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
        )

    def list_issues(self, label: str, state: str = "open", per_page: int = 100) -> list[dict[str, Any]]:
        """Open issues carrying `label` (the detection queue). The issues endpoint
        also returns PRs, so those are filtered out."""
        resp = self.session.get(
            f"{self.base}/issues",
            params={"labels": label, "state": state, "per_page": per_page},
            timeout=self.timeout,
        )
        if resp.status_code != 200:
            return []
        return [it for it in resp.json() if "pull_request" not in it]

    def find_issue_number(self, cve_id: str) -> Optional[int]:
        # Search this repo for the hidden marker in an issue body.
        q = f'repo:{self.repo} type:issue in:body "{marker(cve_id)}"'
        resp = self.session.get(
            "https://api.github.com/search/issues",
            params={"q": q},
            timeout=self.timeout,
        )
        if resp.status_code != 200:
            return None
        items = resp.json().get("items", [])
        return items[0]["number"] if items else None

    def create_issue(self, title: str, body: str, labels: list[str]) -> int:
        resp = self.session.post(
            f"{self.base}/issues",
            json={"title": title, "body": body, "labels": labels},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()["number"]

    def comment(self, number: int, body: str) -> None:
        self.session.post(
            f"{self.base}/issues/{number}/comments",
            json={"body": body},
            timeout=self.timeout,
        ).raise_for_status()

    def close(self, number: int) -> None:
        self.session.patch(
            f"{self.base}/issues/{number}",
            json={"state": "closed", "state_reason": "completed"},
            timeout=self.timeout,
        ).raise_for_status()
