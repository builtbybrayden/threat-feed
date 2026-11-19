# Validation results

Machine-written proof that a detection template actually works, one file per CVE
at `validations/<CVE-ID>/result.json`. These are the **deployment gate**: a
template is only trusted once it has passed the three-control protocol against a
real lab.

These files are produced by the partnering **Hermes** runner on a Docker host —
it stands up the instances, runs the template, applies the gate, and writes the
result here. They are not hand-authored (unlike `decisions.yaml`, which records
what a *human* decided). The pipeline reads them (`pipeline/validation.py`) and
the dashboard shows the outcome, the controls, and the lab's provenance.

## The three-control protocol

A result is `validated: true` only if **all three** hold:

1. `vulnerable_instance` — the template MUST fire (true positive)
2. `patched_control` — the template MUST NOT fire (no false positive on a fix)
3. `negative_control_benign` — the template MUST NOT fire on an unrelated endpoint

## Lab provenance (and honesty about it)

`lab.source` records where the vulnerable/patched instances came from:

- `vulhub` — a curated [vulhub](https://github.com/vulhub/vulhub) environment for
  the CVE. `confidence: high`.
- `docker-hub-inference` — **no curated lab existed**, so the runner pulled images
  from the public Docker registry and chose a *supposed* vulnerable tag and a
  *supposed* patched tag by inferring versions from the CVE's data.
  `confidence: low`, and `lab.note` says so. The dashboard flags these distinctly
  so an inferred pass is never mistaken for a curated one.
- `custom` — a hand-built lab.

## Contract

See the module docstring in [`pipeline/validation.py`](../pipeline/validation.py)
for the full JSON shape. The loader recomputes `validated` and each control's
`pass` from the recorded `detected`/`expect`, so a file cannot claim a pass it
did not earn, and cannot be `validated` while missing a required control.

Everything here is produced against **local lab targets only** (isolated Docker
network); nothing scans external hosts, and a lab demonstration is not an
independent evaluation.
