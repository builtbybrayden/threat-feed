"""Validate the example detection against three controls, locally, in-process.

Protocol (the point of the exercise — a detection is only "validated" if all hold):
  1. vulnerable_instance      -> detection MUST fire      (true positive)
  2. patched_control          -> detection MUST NOT fire  (patched = negative control)
  3. negative_control_benign  -> detection MUST NOT fire  (unrelated endpoint, so the
                                 matcher isn't just matching any 200)

The probe and matcher mirror detection.yaml (GET the traversal path; match status
200 AND the canary in the body), so no external Nuclei binary is required and the
check is reproducible with the standard library alone. Everything runs on
127.0.0.1 against the lab target in this directory — no external scanning.

Run it:  python validation/example_path_traversal/run_validation.py
It writes result.json next to this file and exits non-zero if validation fails.
"""

from __future__ import annotations

import http.client
import json
import os
import sys
import tempfile
import threading
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import labapp  # noqa: E402  (local module next to this script)

PROBE_PATH = "/download?file=../secret.txt"   # mirrors detection.yaml
BENIGN_PATH = "/index.html"                   # a normal request that must not match
HERE = os.path.dirname(os.path.abspath(__file__))


def _get(port: int, path: str) -> tuple[int, str]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        return resp.status, resp.read().decode("utf-8", "replace")
    finally:
        conn.close()


def _detect(port: int, path: str) -> bool:
    """The detection.yaml matcher, in code: status 200 AND canary in body."""
    status, body = _get(port, path)
    return status == 200 and labapp.CANARY in body


def _serve(mode: str, base: str) -> tuple["labapp.HTTPServer", int]:
    server = labapp.make_server(mode, base, port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def run() -> dict:
    base = tempfile.mkdtemp(prefix="tf-lab-")
    labapp.build_root(base)
    vuln_srv, vuln_port = _serve("vulnerable", base)
    patched_srv, patched_port = _serve("patched", base)
    try:
        vuln_hit = _detect(vuln_port, PROBE_PATH)
        patched_hit = _detect(patched_port, PROBE_PATH)
        benign_hit = _detect(vuln_port, BENIGN_PATH)
    finally:
        vuln_srv.shutdown()
        patched_srv.shutdown()

    controls = [
        {"name": "vulnerable_instance", "expect": "detect",
         "detected": vuln_hit, "pass": vuln_hit is True},
        {"name": "patched_control", "expect": "no-detect",
         "detected": patched_hit, "pass": patched_hit is False},
        {"name": "negative_control_benign", "expect": "no-detect",
         "detected": benign_hit, "pass": benign_hit is False},
    ]
    return {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "template": "detection.yaml",
        "probe": PROBE_PATH,
        "canary": labapp.CANARY,
        "controls": controls,
        "validated": all(c["pass"] for c in controls),
        "note": "Self-contained local lab (127.0.0.1). A demonstration of the "
                "validation protocol, not an independent evaluation.",
    }


def main() -> int:
    result = run()
    out = os.path.join(HERE, "result.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    for c in result["controls"]:
        print(f"  {'PASS' if c['pass'] else 'FAIL'}  {c['name']}: "
              f"expected {c['expect']}, detected={c['detected']}")
    print(f"validated={result['validated']}  -> {out}")
    return 0 if result["validated"] else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
