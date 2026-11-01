# Development notes

Engineering log for threat-feed. Observed facts, reproducible checks, and open
work are kept separate on purpose. This file makes no claims about adoption,
impact, or recognition.

## 2026-11-01 — truthful coverage, curated-queue alignment, decision lifecycle

AI-assisted changes (Claude), on branch `truthful-coverage-and-workflow`, not yet
reviewed or merged by a human. Three self-contained commits:

1. **Coverage truthfulness.** Coverage is now three-valued — `covered` / `absent`
   / `unknown` — derived from whether a coverage index was actually available that
   run. A missing or stale index reads as `unknown`, never as a confirmed gap, and
   the headline coverage % is computed only over CVEs whose coverage is known. The
   index can carry provenance (built-at, template count, source) and the dashboard
   labels coverage as a template *reference* index, not validated detection.
2. **Curated queue is the default; auto-filing is opt-in.** The README had claimed
   gaps "automatically" became GitHub Issues, but the default run builds a
   user-curated queue and the sync helper was never called. The helper is now wired
   behind an explicit `--sync-issues` flag (confirmed-absent candidates only), and
   the docs match the implemented behaviour.
3. **Auditable decision lifecycle + local validation.** `decisions.yaml` records,
   per CVE, what a human decided (status, reviewer, date, rationale,
   template/reference, artifacts, outcome). States: candidate → reviewed →
   lab-validated → completed, plus terminal `rejected` / `inconclusive`. A
   reproducible, stdlib-only example in `validation/` validates a detection against
   a vulnerable instance, a patched control, and a benign negative control.

### Reproduce / evaluate independently

```bash
make test                                             # full suite (no network)
python -m pipeline.ingest --offline                   # build site/ from sample_data/
python validation/example_path_traversal/run_validation.py   # local 3-control validation
```

Observed on 2026-11-01: `56 passed`; the validation example reports `validated=True`
(vulnerable detects; patched and benign controls do not). These are facts about
this code and this fixture, nothing more.

**Licence.** The owner chose MIT (root `LICENSE`, `Copyright (c) 2026 Brayden
Arnold`). This was a deliberate decision, not a default.

**CI.** A `pull_request`-triggered workflow (`.github/workflows/ci.yml`) runs the
test suite on every PR so changes are self-checked before merge. It is
read-only (`permissions: contents: read`), does no network ingestion and no
external scanning — it only runs `pytest` and the local validation example.

## Open work (needs a human — not a coding-session deliverable)

- **Real detection cases.** The `validation/` example uses a toy target and a
  synthetic CVE. Three to five end-to-end cases against *real* vulnerable/patched
  builds, each with a recorded decision + result, are a human milestone.
- **Independent evaluation.** A fixture demonstration is not an evaluation. A real
  one needs a dated sample, a defined baseline workflow to compare against, and
  reported denominators, failures and exclusions — run with another engineer.
- **Pilot use.** No independent users or measured benefit are established. Any pilot
  needs a defined workflow, baseline, and success measure agreed before collecting
  results, and must keep employer/internal data out of this public repo.

## Separation of concerns

- *Observed facts*: test results, the validation example's recorded controls, feed
  ingestion counts. These describe the code, not outcomes in the world.
- *Targets / future work*: the items above. They are planning intent, not results,
  and must never be reported as if achieved.
