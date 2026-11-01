# Threat Intelligence Feed → Nuclei Detection Pipeline

A proof-of-concept that does two jobs from free, public data:

1. **Awareness** — aggregates security news, research and vulnerability data into a
   prioritized, mobile-friendly dashboard (installable as an iPhone/Android app).
2. **Detection engineering** — acts as the intake stage of a pipeline that turns new
   vulnerabilities into Nuclei detection templates: for each relevant CVE it answers
   *does a template already exist? if not, here is everything needed to write one.*

The dashboard is a static site (vanilla HTML/CSS/JS) that GitHub Actions rebuilds on a
schedule and publishes to GitHub Pages. The detection queue is **user-curated**: you add a
CVE from the dashboard (which opens a prefilled `detection-queue` GitHub Issue) and the
pipeline lists those issues into the queue. Auto-filing an issue per candidate is available
but **opt-in** (`--sync-issues`), not part of a normal run.

> Two honesty boundaries this project keeps, by design:
> - **Template coverage is a reference index, not validated detection.** "Template indexed"
>   means a Nuclei template references that CVE id — not that the check has been run against
>   a vulnerable and a patched target. Behavioural validation is a separate, recorded step.
> - **A missing/stale coverage index reads as _unknown_, never as a confirmed gap.** Absence
>   of a template is only asserted when the index was actually available that run.

```
GitHub Actions (cron, every 6h)
  └─ Python ingester (pipeline/)
       ├─ RSS/Atom feeds (feedparser)           ← sources in config.yaml
       ├─ CISA KEV catalog
       ├─ FIRST EPSS API (batched)
       ├─ NVD API 2.0 (CWE, CPE, CVSS, refs)    ← optional NVD_API_KEY
       ├─ PoC signals (nomi-sec PoC-in-GitHub, NVD "Exploit" refs)
       └─ Nuclei coverage index (from a shallow clone of nuclei-templates)
  └─ normalize → dedupe (state.json) → tag + score
  └─ detection triage → candidates (coverage: covered / absent / unknown)
  └─ write site/data.json + site/candidates.json → commit → Pages redeploys
  └─ detection queue = open `detection-queue` issues → site/queue.json + briefs/
  └─ (opt-in --sync-issues) file/close nuclei-candidate issues for absent candidates
Static site (mobile-first PWA): "News" + "Threats" + "Detection queue" views
```

## Quick start

```bash
make install            # or: python -m pip install -r requirements.txt
make test               # run the test suite (no network)
make demo               # build from sample_data/ and serve at http://localhost:8000
```

Then open <http://localhost:8000>. On an iPhone, open the Pages URL in Safari and
**Share → Add to Home Screen** to install it as an app (see *iPhone app* below).

On Windows without `make`, run the commands directly:

```bash
./.venv/Scripts/python.exe -m pipeline.ingest --offline
cd site && ../.venv/Scripts/python.exe -m http.server 8000
```

### Running the real pipeline

```bash
make coverage-index     # one-time (or periodic): clone nuclei-templates, build the index
make run                # full online run: feeds + KEV + EPSS + NVD + PoC + triage
```

`python -m pipeline.ingest` flags: `--offline` (use `sample_data/`, no network),
`--no-nvd` (skip the slow NVD enrichment), `--limit-nvd N` (cap NVD lookups this run),
`--no-issues` (never touch GitHub), `--sync-issues` (opt-in: file/close
`nuclei-candidate` issues for confirmed-absent candidates; needs `GITHUB_TOKEN` +
`GITHUB_REPOSITORY`), `--queue-only` (rebuild only the queue from issues). State persists
in `state.json` between runs so re-running produces no duplicate items or issues.

## File layout

```
config.yaml           feeds, source weights, scoring, thresholds (no magic numbers in code)
watchlist.yaml        generic public products/terms to flag
decisions.yaml        auditable detection-decision records (the lifecycle), hand-authored
pipeline/
  models.py           the two schemas: Item and CveRecord
  normalize.py        HTML stripping, CVE regex, id hashing, safe-link + URL canonicalization
  feeds.py  kev.py  epss.py  nvd.py  poc.py   source ingestion/enrichment
  coverage.py         build/load the Nuclei coverage index
  score.py            transparent, config-driven scoring
  triage.py           detectability classification + candidate rule
  briefs.py           per-CVE Markdown + JSON detection briefs
  decisions.py        load/validate the decision-lifecycle records
  issues.py           idempotent GitHub Issues work queue (opt-in --sync-issues)
  state.py            state.json load/save (dedupe + enrichment cache)
  ingest.py           orchestrator + CLI
site/                 static PWA dashboard (index.html, app.js, style.css, sw.js, manifest)
briefs/               generated detection briefs
sample_data/          committed snapshot for the --offline demo
validation/           reproducible local validation example (vuln + patched + controls)
tools/                gen_icons.py (PWA icons), make_sample.py (snapshot sample_data)
tests/                fixtures + unit/integration tests (no live network)
.github/workflows/    pipeline.yml (cron + Pages), validate-templates.yml (phase 2)
```

## Data model

**Item** (one per feed entry), keyed by a stable id = `sha256(source | canonical-url)[:16]`:
`source`, `source_type`, `title`, `url`, `published` (UTC ISO 8601), `summary`
(HTML-stripped), `cves[]`, `tags[]`, `score`, `score_reasons[]`, `kev`, `epss`.

**CveRecord** (one per CVE id): `description`, `cwe[]`, `cvss_vector`, `cvss_score`,
`vendor`/`product`/`cpes[]`, `affected_versions`, `fixed_version`, `references[]`, `kev`,
`epss`, `poc_links[]`, `nuclei_template` (path or `null`), `detection{…}`, `is_candidate`,
`candidate_reasons[]`, `score`, `issue_number`.

## Scoring

Transparent and config-driven (`config.yaml` → `scoring`). Each term that fires is
recorded in `score_reasons[]` and shown on the dashboard under "Why this scored N":

```
score = source_weight
      + kev_bonus                 (if in CISA KEV)
      + epss * epss_weight
      + watchlist_bonus           (once, if any watchlist term hits)
      + poc_bonus                 (if a public PoC is known)
      + recency_max * 0.5 ** (age_days / half_life_days)
# clamped to [0, 100]
```

Defaults: source weights 20 (KEV) / 15 (PortSwigger, Project Zero) / 12 (GitHub Security
Lab) / 8 (tl;dr sec, Risky Bulletin) / 6 (Simon Willison); KEV +40; EPSS weight 30;
watchlist +15; PoC +10; recency up to +15 with a 7-day half-life. Tune freely in config.

## Detection triage and the candidate rule

For every CVE seen, the pipeline classifies detectability (rules-first, explainable):

- `remote_network` — CVSS `AV:N`
- `likely_http` — a web CWE (22/78/79/89/94/287/352/434/502/611/862/918) or a remote
  application CPE
- `has_poc` / `has_technical_writeup` — from PoC index + NVD reference tags
- suggested template type — `behavioral` when HTTP-detectable *and* there's a PoC/writeup
  to model it on, else the safer passive `version-fingerprint`

**A CVE is a candidate** when it is **not covered** (no indexed template, or coverage
unknown) AND is remote- or HTTP-detectable AND carries a priority signal (in KEV, or
EPSS ≥ threshold, or a watchlist product). Candidates are ranked by score and surfaced on
the Threats board and in `site/candidates.json`. A candidate found while coverage was
*unknown* is marked provisional (its reasons say a template "was not ruled out").

Coverage status is three-valued and kept distinct from the template path:
`covered` (a template indexes the CVE), `absent` (the index was available and had none),
`unknown` (no index this run — absence is **not** established). Headline coverage % is
computed only over CVEs whose coverage is known.

## Detection workflow (the decision lifecycle)

Triage decides whether a CVE is a *candidate*. What a human then did about it is
recorded, by hand, in **`decisions.yaml`** at the repo root — one record per CVE. The
pipeline merges these onto the CVE records, so the dashboard and the detection queue show
an auditable trail (status, reviewer, date, rationale, template/reference, artifacts,
outcome), not just "candidate / not candidate".

Lifecycle states: `candidate → reviewed → lab-validated → completed`, plus the terminal
outcomes `rejected` and `inconclusive` (so the trail can honestly end in "we decided not
to" or "we couldn't tell" — not only in successes).

```yaml
- cve: CVE-2099-0999
  status: lab-validated
  reviewer: Brayden Arnold
  date: 2026-11-01
  rationale: HTTP path traversal with a public PoC; a behavioural check is feasible.
  template: validation/example_path_traversal/detection.yaml
  artifacts: [validation/example_path_traversal/result.json]
  outcome: Detected on the vulnerable instance; clean on the patched + negative control.
```

**Local validation.** `lab-validated` means a detection was exercised against a vulnerable
instance, a patched control, and a benign negative control — locally, on `127.0.0.1`, and
recorded. `validation/example_path_traversal/` is a reproducible, stdlib-only worked
example of exactly that protocol:

```bash
python validation/example_path_traversal/run_validation.py   # writes result.json; exits non-zero on failure
```

It demonstrates the protocol; it is **not** an independent evaluation of the tool, and its
CVE id is synthetic. To validate a real CVE, swap in the real vulnerable/patched builds and
point the template at the real request — keeping the same three controls, and keeping it
local and authorised (never run a candidate detection against live or shared hosts).

## Dashboard

A black/white/gray, high-contrast UI (X timeline structure, Apple-grade restraint) with
three views and an AppSec-focused headline:

- **News** — the reading timeline: newsletters, research and commentary as X-style posts
  (real source avatars, score pill, CVE chips, inline KEV/EPSS/PoC + ecosystem/vuln-class
  tags, expandable score reasons), with search and tag filters.
- **Threats** — a CVE-centric intelligence board: active & recent application-security
  vulnerabilities ranked by priority (exploited in the wild, EPSS, public PoC, ecosystem
  relevance), newest-exploited first, each showing coverage status (**Template indexed** /
  **No template** / **Coverage unknown**), ecosystem/class tags, and any feed coverage.
  Filter by coverage or ecosystem.
- **Detection queue** — the detection backlog: AppSec vulns with no Nuclei template yet
  (the gaps), with detectability, suggested template type, a brief, and the tracking issue.
- **Headline KPIs** — Actively exploited (AppSec ∩ KEV), Newly exploited (added to KEV in
  the last 30d), Public PoC, Detection gaps.
- **Right rail** — top detection gaps and trending tags.

Feed split: an item is a **Threat** when it names a CVE and carries a priority signal
(KEV, high EPSS, public PoC, or an AppSec product); multi-CVE newsletter roundups stay in
**News**. The whole pipeline re-ranks toward application security (package ecosystems,
web frameworks, languages, DAST vuln classes) via `watchlist.yaml` and an AppSec scoring
bonus, without dropping anything.

### iPhone app (PWA)

The dashboard is a Progressive Web App, so there's no App Store, no Xcode, and no second
codebase. On iPhone, open the GitHub Pages URL in Safari and **Share → Add to Home
Screen**: it installs with its own icon, launches full-screen (standalone), and the
service worker (`site/sw.js`) caches the app shell and the last data sync so it still
opens with no signal. The "Updated N ago" line keeps staleness honest.

## Security notes (this is read by an appsec audience)

- Feed content is treated as untrusted: HTML is stripped in Python, and the site renders
  every value with `textContent` (never `innerHTML`). Only `http`/`https` links are ever
  stored or rendered. A restrictive `Content-Security-Policy` meta tag (`default-src
  'none'`) locks the page to same-origin scripts/styles/data.
- Every network request has a timeout, retries with backoff, and per-source error
  isolation — one dead source never fails the run.
- The Actions workflow uses least-privilege `permissions:` per job, pins third-party
  actions to full commit SHAs, and uses no `pull_request_target`.
- Secrets (NVD, GitHub) come from env vars / Actions secrets, never from code.
- Generated templates are only ever **validated** (`nuclei -validate`) in CI; behavioural
  runs happen locally against lab containers, never against live or shared hosts.

## Deploying to GitHub Pages

1. Create a public repo and push this project.
2. Settings → Pages → Build and deployment → **GitHub Actions**.
3. (Optional) add an `NVD_API_KEY` repo secret to raise the NVD rate limit.
4. The `pipeline` workflow runs every 6h (and on manual dispatch): it rebuilds the
   coverage index, runs the pipeline, commits refreshed data, and deploys the site.

## Next steps (phase 2: template drafting)

Interfaces are scaffolded; implement after the demo core is proven:

- `drafts/` — candidate templates generated from a brief (start with a deterministic
  version-fingerprint scaffold; an optional LLM drafter behind a clean interface, key from
  env).
- Validation harness — `nuclei -validate` (wired in `validate-templates.yml`), then run
  against a vulnerable lab container (expect a match) and a patched one (expect none) via
  docker compose; record results in the decision record. The three-control protocol and a
  reproducible stdlib-only worked example already exist in `validation/` — generalise it
  from the toy target to real vulnerable/patched builds.
- Only http/dns/network protocols; no `code` templates; no destructive payloads; drafts
  are never auto-promoted — a human reviews and merges via PR.
