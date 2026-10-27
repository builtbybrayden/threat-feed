# Threat Intelligence Feed → Nuclei Detection Pipeline

A proof-of-concept that does two jobs from free, public data:

1. **Awareness** — aggregates security news, research and vulnerability data into a
   prioritized, mobile-friendly dashboard (installable as an iPhone/Android app).
2. **Detection engineering** — acts as the intake stage of a pipeline that turns new
   vulnerabilities into Nuclei detection templates: for each relevant CVE it answers
   *does a template already exist? if not, here is everything needed to write one.*

The dashboard is a static site (vanilla HTML/CSS/JS) that GitHub Actions rebuilds on a
schedule and publishes to GitHub Pages. New detection gaps automatically become labeled
GitHub Issues — the work queue.

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
  └─ detection triage → candidates + per-CVE briefs/
  └─ write site/data.json + site/candidates.json → commit → Pages redeploys
  └─ open/update GitHub Issues for new template candidates
Static site (mobile-first PWA): "Feed" view + "Detection queue" view
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
`--no-issues` (never touch GitHub). State persists in `state.json` between runs so
re-running produces no duplicate items or issues.

## File layout

```
config.yaml           feeds, source weights, scoring, thresholds (no magic numbers in code)
watchlist.yaml        generic public products/terms to flag
pipeline/
  models.py           the two schemas: Item and CveRecord
  normalize.py        HTML stripping, CVE regex, id hashing, safe-link + URL canonicalization
  feeds.py  kev.py  epss.py  nvd.py  poc.py   source ingestion/enrichment
  coverage.py         build/load the Nuclei coverage index
  score.py            transparent, config-driven scoring
  triage.py           detectability classification + candidate rule
  briefs.py           per-CVE Markdown + JSON detection briefs
  issues.py           idempotent GitHub Issues work queue
  state.py            state.json load/save (dedupe + enrichment cache)
  ingest.py           orchestrator + CLI
site/                 static PWA dashboard (index.html, app.js, style.css, sw.js, manifest)
briefs/               generated detection briefs
sample_data/          committed snapshot for the --offline demo
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

**A CVE is a candidate** when it has **no existing Nuclei template** AND is remote- or
HTTP-detectable AND carries a priority signal (in KEV, or EPSS ≥ threshold, or a watchlist
product). Candidates are ranked by score, written as briefs (`briefs/CVE-*.md`), surfaced
in the Detection queue, and opened as GitHub Issues.

## Dashboard

- **Feed view** — cards sorted by score; tag filter chips; search; last-updated; KEV
  badge; EPSS %; expandable score reasons.
- **Detection queue view** — ranked candidates with CVE, product, coverage status
  (template exists / **GAP**), detectability, PoC, suggested template type, a link to the
  brief, and the tracking issue number.
- **Headline stats** — KEV CVEs tracked, % with Nuclei coverage, open gaps, feed items.

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
  docker compose; record results in the brief.
- Only http/dns/network protocols; no `code` templates; no destructive payloads; drafts
  are never auto-promoted — a human reviews and merges via PR.
