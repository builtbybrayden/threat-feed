"""Pipeline orchestrator + CLI.

Runs the whole flow: ingest feeds + KEV -> enrich (EPSS/NVD/PoC/coverage) ->
score + tag -> detection triage -> candidates + briefs -> site JSON -> GitHub
Issues (CI only). Each network source is isolated so one failure never fails
the run. `--offline` runs the identical scoring/triage logic against committed
sample_data/ fixtures, so the demo works with no network.

Usage:
    python -m pipeline.ingest                 # full online run
    python -m pipeline.ingest --offline       # demo from sample_data/
    python -m pipeline.ingest --no-nvd        # skip the slow NVD enrichment
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

from . import coverage as coverage_mod
from . import epss as epss_mod
from . import feeds as feeds_mod
from . import kev as kev_mod
from . import nvd as nvd_mod
from . import poc as poc_mod
from .briefs import write_brief
from .issues import RestGitHubClient, sync_candidates
from .models import Item
from .score import score_cve, score_item
from .state import State
from .triage import classify, evaluate_candidate
from .util import ROOT, load_config, load_watchlist, make_session, now_iso, word_boundary_hits

log = logging.getLogger("pipeline")


# ---------------------------------------------------------------------------
# Source gathering (each returns plain data; online vs offline chosen by flag)
# ---------------------------------------------------------------------------
def _load_sample(sample_dir: Path, name: str, default: Any) -> Any:
    p = sample_dir / name
    if not p.exists():
        return default
    with open(p, "r", encoding="utf-8") as fh:
        return json.load(fh)


def gather_feed_items(cfg, session, offline, sample_dir) -> list[Item]:
    if offline:
        return [Item.from_dict(d) for d in _load_sample(sample_dir, "items.json", [])]
    timeout = cfg["http"]["timeout"]
    items: list[Item] = []
    for feed in cfg["feeds"]:
        try:
            fetched = feeds_mod.fetch_feed(feed, session, timeout)
            items.extend(fetched)
            log.info("feed ok: %s (%d items)", feed["name"], len(fetched))
        except Exception as exc:  # per-source isolation
            log.warning("feed FAILED: %s (%s) — skipping", feed["name"], exc)
    return items


def gather_kev(cfg, session, offline, sample_dir) -> dict[str, dict]:
    try:
        if offline:
            return kev_mod.parse_kev(_load_sample(sample_dir, "kev.json", {}))
        return kev_mod.fetch_kev(cfg["kev"]["url"], session, cfg["http"]["timeout"])
    except Exception as exc:
        log.warning("KEV fetch failed (%s) — continuing without it", exc)
        return {}


def gather_epss(cve_ids, cfg, session, offline, sample_dir) -> dict[str, float]:
    try:
        if offline:
            return epss_mod.parse_epss(_load_sample(sample_dir, "epss.json", {}))
        return epss_mod.fetch_epss(
            cve_ids,
            cfg["epss"]["url"],
            session,
            cfg["http"]["timeout"],
            cfg["epss"].get("batch_size", 100),
        )
    except Exception as exc:
        log.warning("EPSS fetch failed (%s) — continuing without it", exc)
        return {}


def load_coverage(cfg, offline, sample_dir) -> dict[str, str]:
    if offline:
        return {k.upper(): v for k, v in _load_sample(sample_dir, "coverage_index.json", {}).items()}
    return coverage_mod.load_index(ROOT / cfg["coverage"]["index_cache"])


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------
def run(args: argparse.Namespace) -> dict[str, Any]:
    cfg = load_config(args.config)
    watchlist = load_watchlist(args.watchlist)
    sample_dir = Path(args.sample)
    state = State.load(args.state)
    session = None if args.offline else make_session(cfg)

    # 1. Feeds + KEV --------------------------------------------------------
    items = gather_feed_items(cfg, session, args.offline, sample_dir)
    new_count = sum(state.upsert_item(it) for it in items)
    kev_map = gather_kev(cfg, session, args.offline, sample_dir)

    # 2. Collect every CVE referenced, create records, apply KEV -----------
    all_cves: set[str] = set()
    for it in state.items.values():
        all_cves.update(it.cves)
    all_cves.update(kev_map.keys())  # KEV CVEs are tracked even if no feed mentions them
    for cve in all_cves:
        rec = state.get_cve(cve)
        if cve in kev_map:
            rec.kev = True
            k = kev_map[cve]
            rec.vendor = rec.vendor or k.get("vendor")
            rec.product = rec.product or k.get("product")

    # 3. EPSS (batched) ----------------------------------------------------
    epss_map = gather_epss(all_cves, cfg, session, args.offline, sample_dir)
    for cve, val in epss_map.items():
        if cve in state.cves:
            state.cves[cve].epss = val

    # 4. Coverage index ----------------------------------------------------
    coverage = load_coverage(cfg, args.offline, sample_dir)
    for cve, rec in state.cves.items():
        rec.nuclei_template = coverage.get(cve)

    # 5. NVD enrichment (cached by TTL) + PoC ------------------------------
    _enrich_nvd_poc(state, cfg, session, args, sample_dir, all_cves)

    # 6. Score + tag items; track which CVEs hit the watchlist -------------
    watchlist_cves: set[str] = set()
    for it in state.items.values():
        it.kev = any(c in kev_map for c in it.cves)
        epss_vals = [state.cves[c].epss for c in it.cves if state.cves.get(c) and state.cves[c].epss is not None]
        it.epss = max(epss_vals) if epss_vals else None
        has_poc = any(state.cves.get(c) and state.cves[c].poc_links for c in it.cves)
        it.score, it.score_reasons, hits = score_item(it, cfg, watchlist, has_poc=has_poc)
        it.tags = _tags_for_item(it, hits, has_poc)
        if hits:
            watchlist_cves.update(it.cves)

    # 7. Triage + candidates ----------------------------------------------
    cve_to_itemscore: dict[str, float] = defaultdict(float)
    for it in state.items.values():
        for c in it.cves:
            cve_to_itemscore[c] = max(cve_to_itemscore[c], it.score)

    candidates = []
    for cve, rec in state.cves.items():
        # Rank by whichever is higher: a linking item's score, or the CVE's own
        # intrinsic priority (so uncovered KEV CVEs no outlet covered still rank).
        rec.score = max(round(cve_to_itemscore.get(cve, 0.0), 1), score_cve(rec, cfg))
        classify(rec, cfg)
        wl_hit = cve in watchlist_cves or bool(
            word_boundary_hits(f"{rec.vendor or ''} {rec.product or ''} {rec.description}", watchlist)
        )
        rec.is_candidate, rec.candidate_reasons = evaluate_candidate(rec, cfg, watchlist_hit=wl_hit)
        rec.last_updated = now_iso()
        if rec.is_candidate:
            candidates.append(rec)
    candidates.sort(key=lambda r: (r.score, r.kev, r.epss or 0), reverse=True)

    # 8. Briefs ------------------------------------------------------------
    for rec in candidates:
        write_brief(rec, args.briefs)

    # 9. Site JSON ---------------------------------------------------------
    stats = _compute_stats(state, candidates)
    _write_site(state, candidates, stats, args.site)

    # 10. Issues (CI only) -------------------------------------------------
    issue_summary = _maybe_sync_issues(state, candidates, cfg, args)

    state.save(args.state)

    summary = {
        "new_items": new_count,
        "total_items": len(state.items),
        "total_cves": len(state.cves),
        "candidates": len(candidates),
        "issues": issue_summary,
        "stats": stats,
    }
    log.info("run complete: %s", json.dumps(summary["stats"]))
    return summary


def _enrich_nvd_poc(state, cfg, session, args, sample_dir, all_cves) -> None:
    if args.offline:
        nvd_fixture = _load_sample(sample_dir, "nvd.json", {})
        poc_fixture = _load_sample(sample_dir, "poc.json", {})
        for cve, rec in state.cves.items():
            if cve in nvd_fixture:
                _apply_nvd(rec, nvd_fixture[cve])
            rec.poc_links = poc_fixture.get(cve, rec.poc_links)
        return

    if args.no_nvd:
        log.info("NVD enrichment skipped (--no-nvd)")
        return

    delay = nvd_mod.throttle_delay(cfg)
    ttl = cfg["nvd"].get("cache_ttl", 604800)
    budget = args.limit_nvd
    done = 0
    # Enrich highest-priority first: KEV, then EPSS, so a budget still covers what matters.
    ordered = sorted(
        state.cves.values(),
        key=lambda r: (r.kev, r.epss or 0),
        reverse=True,
    )
    for rec in ordered:
        if budget is not None and done >= budget:
            break
        if not _nvd_stale(rec, ttl):
            continue
        try:
            fields = nvd_mod.fetch_cve(rec.cve_id, cfg["nvd"]["url"], session, cfg["http"]["timeout"])
            if fields:
                _apply_nvd(rec, fields)
            rec.nvd_fetched_at = now_iso()
            done += 1
        except Exception as exc:
            log.warning("NVD enrich failed for %s (%s)", rec.cve_id, exc)
            continue
        finally:
            nvd_mod.sleep(delay)
        try:
            rec.poc_links = poc_mod.fetch_poc(
                rec.cve_id, cfg["poc"]["base_url"], session, cfg["http"]["timeout"]
            )
        except Exception as exc:
            log.warning("PoC lookup failed for %s (%s)", rec.cve_id, exc)


def _nvd_stale(rec, ttl: int) -> bool:
    from .util import age_days
    if rec.nvd_fetched_at is None:
        return True
    return age_days(rec.nvd_fetched_at) * 86400 > ttl


def _apply_nvd(rec, fields: dict[str, Any]) -> None:
    rec.description = fields.get("description") or rec.description
    rec.cwe = fields.get("cwe") or rec.cwe
    rec.cvss_vector = fields.get("cvss_vector") or rec.cvss_vector
    rec.cvss_score = fields.get("cvss_score") if fields.get("cvss_score") is not None else rec.cvss_score
    rec.vendor = fields.get("vendor") or rec.vendor
    rec.product = fields.get("product") or rec.product
    rec.cpes = fields.get("cpes") or rec.cpes
    rec.references = fields.get("references") or rec.references


def _tags_for_item(it: Item, hits: list[str], has_poc: bool) -> list[str]:
    tags = []
    if it.kev:
        tags.append("KEV")
    if it.source_type == "research":
        tags.append("research")
    if hits:
        tags.append("watchlist")
        # AI-sec tag when an AI/LLM term matched.
        if any(h in ("prompt injection", "llm", "rag", "mcp", "model context protocol", "langchain") for h in hits):
            tags.append("AI-sec")
    low = f"{it.title} {it.summary}".lower()
    if "supply chain" in low or "dependency" in low:
        tags.append("supply-chain")
    if has_poc:
        tags.append("has-PoC")
    if it.cves:
        tags.append("has-CVE")
    return tags


def _compute_stats(state: State, candidates: list) -> dict[str, Any]:
    kev_records = [r for r in state.cves.values() if r.kev]
    kev_covered = [r for r in kev_records if r.nuclei_template]
    pct = round(100 * len(kev_covered) / len(kev_records), 1) if kev_records else 0.0
    return {
        "kev_tracked": len(kev_records),
        "kev_with_coverage": len(kev_covered),
        "kev_coverage_pct": pct,
        "open_gaps": len(candidates),
        "total_items": len(state.items),
        "total_cves": len(state.cves),
    }


def _write_site(state: State, candidates: list, stats: dict, site_dir: str) -> None:
    site = Path(site_dir)
    site.mkdir(parents=True, exist_ok=True)
    generated = now_iso()

    items_sorted = sorted(state.items.values(), key=lambda i: i.score, reverse=True)
    data = {
        "generated": generated,
        "last_run": state.meta.get("last_run", generated),
        "stats": stats,
        "items": [i.to_dict() for i in items_sorted[:400]],
    }
    _dump(site / "data.json", data)

    cand = {
        "generated": generated,
        "stats": stats,
        "candidates": [_candidate_view(r) for r in candidates],
    }
    _dump(site / "candidates.json", cand)


def _candidate_view(rec) -> dict[str, Any]:
    return {
        "cve_id": rec.cve_id,
        "vendor": rec.vendor,
        "product": rec.product,
        "score": rec.score,
        "kev": rec.kev,
        "epss": rec.epss,
        "cvss_score": rec.cvss_score,
        "cwe": rec.cwe,
        "detectability": {
            "remote_network": rec.detection.remote_network,
            "likely_http": rec.detection.likely_http,
            "has_poc": rec.detection.has_poc,
            "suggested_template_type": rec.detection.suggested_template_type,
        },
        "nuclei_template": rec.nuclei_template,
        "brief": f"briefs/{rec.cve_id}.md",
        "issue_number": rec.issue_number,
        "candidate_reasons": rec.candidate_reasons,
    }


def _dump(path: Path, data: Any) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2, sort_keys=True)


def _maybe_sync_issues(state, candidates, cfg, args) -> dict[str, Any]:
    import os
    if args.offline or args.no_issues:
        return {"skipped": "offline/--no-issues"}
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not (token and repo):
        return {"skipped": "no GITHUB_TOKEN/GITHUB_REPOSITORY"}
    client = RestGitHubClient(repo, token, make_session(cfg), cfg["http"]["timeout"])
    try:
        return sync_candidates(candidates, state.cves, client)
    except Exception as exc:
        log.warning("issue sync failed (%s)", exc)
        return {"error": str(exc)}


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Threat-feed ingestion + detection-triage pipeline.")
    ap.add_argument("--offline", action="store_true", help="run from sample_data/ with no network")
    ap.add_argument("--no-nvd", action="store_true", help="skip NVD enrichment (faster)")
    ap.add_argument("--no-issues", action="store_true", help="never touch GitHub Issues")
    ap.add_argument("--limit-nvd", type=int, default=None, help="max NVD lookups this run")
    ap.add_argument("--config", default=str(ROOT / "config.yaml"))
    ap.add_argument("--watchlist", default=str(ROOT / "watchlist.yaml"))
    ap.add_argument("--state", default=str(ROOT / "state.json"))
    ap.add_argument("--site", default=str(ROOT / "site"))
    ap.add_argument("--briefs", default=str(ROOT / "briefs"))
    ap.add_argument("--sample", default=str(ROOT / "sample_data"))
    ap.add_argument("--verbose", "-v", action="store_true")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    summary = run(args)
    print(json.dumps(summary["stats"], indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
