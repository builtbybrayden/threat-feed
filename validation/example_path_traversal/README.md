# Local validation example — path traversal

A worked, self-contained example of **validating a detection locally** against a
vulnerable instance, a patched control, and a benign negative control. It is the
reference for what "lab-validated" means in `decisions.yaml`: a recorded result
with three controls, not a template that merely parses.

> **Scope.** Everything runs on `127.0.0.1` with the Python standard library.
> There is no external target and no real CVE — the "secret" is a generated
> canary, not a credential. This demonstrates the *protocol*; it is not an
> independent evaluation of the tool.

## Files

| File | What it is |
|---|---|
| `labapp.py` | the lab target: `GET /download?file=<name>`, `--mode vulnerable\|patched` |
| `detection.yaml` | the shippable Nuclei template (the detection artifact) |
| `run_validation.py` | runs the three controls in-process and writes `result.json` |
| `result.json` | the recorded outcome of the last run (the audit artifact) |

## Run it

```bash
python validation/example_path_traversal/run_validation.py
```

It prints PASS/FAIL per control and writes `result.json`. Exit code is non-zero if
validation fails, so it works in CI.

To poke the target by hand:

```bash
python validation/example_path_traversal/labapp.py --mode vulnerable --port 8080
# leaks the canary:
curl "http://127.0.0.1:8080/download?file=../secret.txt"
# patched mode refuses the same request:
python validation/example_path_traversal/labapp.py --mode patched --port 8081
curl -i "http://127.0.0.1:8081/download?file=../secret.txt"   # 403
```

## The protocol (why three controls)

1. **vulnerable_instance** — the detection MUST fire (true positive).
2. **patched_control** — the SAME probe MUST NOT fire against a fixed instance
   (guards against a check that always matches).
3. **negative_control_benign** — an unrelated request MUST NOT fire (guards
   against a matcher that trips on any `200`).

A detection is recorded as `lab-validated` only when all three hold. The result
is linked from the CVE's record in `decisions.yaml` under `artifacts:`.

## Adapting this for a real CVE

Replace `labapp.py` with the real vulnerable and patched builds (e.g. two
`docker compose` services, or two tagged container images), point `detection.yaml`
at the real request/matcher, and keep the same three-control protocol. Keep it
local and authorised — never run a candidate detection against live or shared
hosts.
