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

## 2026-11-01 — CVE List v5 intake (authoritative CVE discovery) + provenance

AI-assisted (Claude). Adds the MITRE CVE List (`github.com/CVEProject/cvelistV5`)
as a discovery stream so a webapp CVE appears here when its CNA publishes it,
rather than whenever NVD/GHSA catch up. Design decisions, for the record:

- **Bounded fetch, not a clone.** The repo publishes an hourly GitHub Release with
  a small `*_delta_CVEs_*.zip` (~1-2 MB, changes since midnight UTC) next to a
  ~650 MB all-CVEs bundle. `pipeline/cvelist.py` pulls only the delta bundle — one
  request, no per-record fan-out, no 300k-file clone. Endpoints were verified to
  resolve on 2026-11-01; a live `fetch_recent` returned 15 webapp records in ~2 s.
- **Untrusted-input handling.** The downloaded zip is read in memory with
  `ZipFile.read` only (never extracted, so no path traversal), with caps on the
  download size, per-member uncompressed size, and total bytes read (zip-bomb
  guards). Tests cover a bad zip, an oversized member, and the manifest-skip.
- **Webapp scope.** Only application-security-relevant records are imported,
  reusing the shared `appsec` classifier/CWE set so "relevant" means the same
  thing as everywhere else. The hardware/physical-access noise that fills the raw
  CVE firehose is dropped at ingest.
- **Provenance.** `CveRecord.sources[]` now records which intake streams saw each
  CVE (`feed`/`kev`/`ghsa`/`cvelist`/`nvd`), surfaced as `origins` in the site
  JSON. This keeps "where did this come from" answerable now that several sources
  can contribute to one record. (UI badges for `origins` are a follow-up; the data
  is already in `data.json`/`candidates.json`.)

Observed on 2026-11-01: `67 passed` (was 56; +11 for cvelist and provenance). The
new source is isolated like every other — a fetch failure logs and continues.

Open follow-up (not done here): OSV.dev and a WordPress/Wordfence feed are the
next two webapp discovery sources; and `origins` could be shown on the dashboard
cards. Neither is required for this change to stand on its own.

## 2026-11-01 — OSV.dev intake (language-ecosystem vulnerability DBs)

AI-assisted (Claude). Adds OSV.dev (`pipeline/osv.py`) for the language databases
GHSA only partly mirrors: RustSec (crates.io), the Go vuln DB, Hex (Elixir), Pub
(Dart). Decisions:

- **Bounded, non-overlapping fetch.** OSV publishes per-ecosystem `all.zip`
  exports in a public GCS bucket. We pull only the small language-DB ecosystems
  (crates.io ~4 MB, Go ~13 MB, Hex ~1 MB, Pub ~30 KB) — never npm (~220 MB) or
  PyPI (~38 MB), which GHSA already covers and which would dominate the run. Same
  untrusted-zip guards as the CVE-List intake (read-only, size/entry/total caps).
- **Keyed by CVE alias.** OSV records key on their own id (GHSA-/RUSTSEC-/GO-…);
  we take the CVE from each record's `aliases` and skip records with no CVE and
  withdrawn records. Only records `modified` within a 45-day window are kept, so
  one bounded download yields a bounded recent set; duplicates across ecosystems
  are collapsed to the newest.
- **Treated as AppSec, like GHSA.** An OSV record is a package-ecosystem vuln, so
  its CVE is forced `appsec=True` (and its ecosystem tag unioned in) even when its
  own text/CWE would not classify — mirroring the GHSA path. `origins` gains the
  `osv` tag.

Endpoints verified to resolve 2026-11-01; a live `fetch_recent` returned 12 recent
records across rust/go/hex in ~3 s. Observed: `76 passed` (was 67; +9 for OSV).

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
