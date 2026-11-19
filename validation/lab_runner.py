"""Generalized detection validator: run a real Nuclei template against the
three controls and write the ``validations/<CVE>/result.json`` contract.

This is the protocol executor the partnering Hermes Docker runner mirrors. Where
``example_path_traversal/run_validation.py`` is an in-process demonstration that
needs no Nuclei binary, this one drives the actual ``nuclei`` CLI against live
URLs, so it validates the template the scanner will really ship:

    vulnerable_instance      -> nuclei MUST report a finding   (true positive)
    patched_control          -> nuclei MUST NOT                (patched negative)
    negative_control_benign  -> nuclei MUST NOT                (a clean service, so
                                 the matcher isn't trivially matching any target)

Usage (all URLs must be local lab targets — 127.0.0.1 / an isolated Docker
network; this never scans external hosts, per CLAUDE.md):

    python validation/lab_runner.py \
        --cve CVE-2099-0001 --template path/to/template.yaml \
        --vulnerable-url http://127.0.0.1:8001 \
        --patched-url    http://127.0.0.1:8002 \
        --benign-url     http://127.0.0.1:8003 \
        --lab-source vulhub --vulnerable-version 2.3.0 --patched-version 2.3.1 \
        --out validations/CVE-2099-0001/result.json

The emitted file follows the contract in ``pipeline/validation.py``; that loader
recomputes ``pass``/``validated`` on read, so this writer only records what each
control actually ``detected`` and lets the single source of truth decide.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Optional

# The three controls and what each must do, matching pipeline/validation.py.
EXPECT = {
    "vulnerable_instance": "detect",
    "patched_control": "no-detect",
    "negative_control_benign": "no-detect",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _nuclei_bin() -> str:
    b = os.environ.get("NUCLEI_BIN") or shutil.which("nuclei")
    if not b:
        raise RuntimeError("nuclei binary not found (set NUCLEI_BIN or add it to PATH)")
    return b


def run_nuclei(template: str, target_url: str, *, timeout: int = 10, hard_timeout: int = 120) -> bool:
    """Run one template against one target; return True iff nuclei reports a match.

    Findings are emitted as JSONL on stdout (``-jsonl``); any finding line means
    the template fired. ``-disable-update-check`` keeps the run offline/hermetic.
    """
    cmd = [
        _nuclei_bin(), "-t", template, "-u", target_url,
        "-jsonl", "-silent", "-no-color", "-disable-update-check",
        "-timeout", str(timeout),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=hard_timeout)
    except subprocess.TimeoutExpired:
        # A hung target is not a detection; treat as no-detect so the gate fails
        # safe (a template that can't complete against the vuln instance won't pass).
        return False
    return any(ln.strip().startswith("{") for ln in proc.stdout.splitlines())


def make_control(name: str, detected: bool) -> dict[str, Any]:
    expect = EXPECT.get(name, "detect")
    passed = (detected is True) if expect == "detect" else (detected is False)
    return {"name": name, "expect": expect, "detected": bool(detected), "pass": passed}


def build_result(
    cve_id: str,
    template: str,
    detected: dict[str, bool],
    *,
    lab: Optional[dict[str, Any]] = None,
    runner: str = "nuclei",
    generated: Optional[str] = None,
) -> dict[str, Any]:
    """Assemble the result.json contract from per-control detection outcomes.
    ``detected`` maps control name -> bool (missing controls are simply omitted,
    which the reader treats as an incomplete, non-validated run)."""
    controls = [make_control(n, detected[n]) for n in EXPECT if n in detected]
    all_pass = bool(controls) and all(c["pass"] for c in controls) and set(detected) >= set(EXPECT)
    return {
        "cve_id": cve_id.upper(),
        "template": template,
        "validated": all_pass,
        "controls": controls,
        "lab": lab or {"source": "custom", "confidence": "low"},
        "runner": runner,
        "generated": generated or _now_iso(),
        "note": "Local lab only (127.0.0.1 / isolated network); not an independent evaluation.",
    }


def validate(
    cve_id: str,
    template: str,
    vulnerable_url: str,
    patched_url: Optional[str],
    benign_url: Optional[str],
    *,
    lab: Optional[dict[str, Any]] = None,
    timeout: int = 10,
) -> dict[str, Any]:
    """Run the template against each available control and build the result.

    A patched and a benign control are both required for a validated pass; when
    one is not provided it is left out and the result cannot be ``validated``.
    """
    detected: dict[str, bool] = {"vulnerable_instance": run_nuclei(template, vulnerable_url, timeout=timeout)}
    if patched_url:
        detected["patched_control"] = run_nuclei(template, patched_url, timeout=timeout)
    if benign_url:
        detected["negative_control_benign"] = run_nuclei(template, benign_url, timeout=timeout)
    return build_result(cve_id, template, detected, lab=lab)


def _lab_from_args(args: argparse.Namespace) -> dict[str, Any]:
    lab: dict[str, Any] = {"source": args.lab_source}
    if args.vulnerable_version or args.vulnerable_image:
        lab["vulnerable"] = {"image": args.vulnerable_image, "version": args.vulnerable_version}
    if args.patched_version or args.patched_image:
        lab["patched"] = {"image": args.patched_image, "version": args.patched_version}
    return lab


def _main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Validate a Nuclei template against the 3 controls.")
    ap.add_argument("--cve", required=True)
    ap.add_argument("--template", required=True, help="path to the Nuclei template")
    ap.add_argument("--vulnerable-url", required=True)
    ap.add_argument("--patched-url")
    ap.add_argument("--benign-url")
    ap.add_argument("--lab-source", default="custom", choices=["vulhub", "docker-hub-inference", "custom"])
    ap.add_argument("--vulnerable-image")
    ap.add_argument("--vulnerable-version")
    ap.add_argument("--patched-image")
    ap.add_argument("--patched-version")
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--out", help="write result.json here (default: stdout)")
    args = ap.parse_args(argv)

    result = validate(
        args.cve, args.template, args.vulnerable_url, args.patched_url, args.benign_url,
        lab=_lab_from_args(args), timeout=args.timeout,
    )
    payload = json.dumps(result, ensure_ascii=False, indent=2)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")
    print(payload)
    return 0 if result["validated"] else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(_main())
