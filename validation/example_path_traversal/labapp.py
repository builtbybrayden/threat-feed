"""A tiny, self-contained lab target for validating a detection locally.

It serves files from a `webroot/` and exposes `GET /download?file=<name>`. In
`vulnerable` mode the filename is used without normalization, so `../secret.txt`
escapes the webroot and leaks a canary string. In `patched` mode the path is
normalized and confined to the webroot, so the same request is refused.

This exists ONLY so a detection can be exercised against a vulnerable instance, a
patched control, and a benign negative-control endpoint — all on 127.0.0.1, with
no external target. Nothing here is a real product or a real CVE; the "secret" is
a generated canary, not a credential. Stdlib only, so it is reproducible anywhere
Python runs.
"""

from __future__ import annotations

import argparse
import os
import posixpath
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, unquote, urlparse

# The marker a detection looks for. If a response body contains this, the
# traversal succeeded in reading a file outside the webroot.
CANARY = "TOP-SECRET-CANARY-7b3f2a"


def build_root(base: str) -> None:
    """Lay out the lab filesystem under ``base``: a webroot with a benign page,
    and a secret.txt one level up (the traversal target)."""
    webroot = os.path.join(base, "webroot")
    os.makedirs(webroot, exist_ok=True)
    with open(os.path.join(webroot, "index.html"), "w", encoding="utf-8") as fh:
        fh.write("<h1>Demo app</h1>\n")
    with open(os.path.join(base, "secret.txt"), "w", encoding="utf-8") as fh:
        fh.write(CANARY + "\nsimulated credential material (not real)\n")


class _Handler(BaseHTTPRequestHandler):
    mode = "patched"
    base = "."

    def log_message(self, *args):  # keep the lab quiet
        pass

    def do_GET(self):  # noqa: N802 (http.server API)
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            return self._send(200, "<h1>Demo app</h1>\n")
        if u.path != "/download":
            return self._send(404, "not found\n")

        name = unquote((parse_qs(u.query).get("file") or [""])[0])
        webroot = os.path.join(self.base, "webroot")
        if self.mode == "vulnerable":
            target = os.path.join(webroot, name)  # no normalization: traversal works
        else:
            safe = posixpath.normpath("/" + name).lstrip("/")
            target = os.path.join(webroot, safe)
            if not os.path.abspath(target).startswith(os.path.abspath(webroot) + os.sep):
                return self._send(403, "forbidden\n")
        try:
            with open(target, "r", encoding="utf-8", errors="replace") as fh:
                return self._send(200, fh.read())
        except OSError:
            return self._send(404, "not found\n")

    def _send(self, code: int, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def make_server(mode: str, base: str, port: int = 0) -> HTTPServer:
    """Build an HTTPServer bound to 127.0.0.1 serving in ``mode``. ``port=0``
    asks the OS for a free port (read it back from ``server.server_address``)."""
    handler = type("Handler", (_Handler,), {"mode": mode, "base": base})
    return HTTPServer(("127.0.0.1", port), handler)


def _main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run the path-traversal lab target.")
    ap.add_argument("--mode", choices=["vulnerable", "patched"], default="vulnerable")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--base", default=None, help="lab filesystem root (default: a temp dir)")
    args = ap.parse_args(argv)
    base = args.base or os.path.join(os.path.dirname(os.path.abspath(__file__)), "_labroot")
    build_root(base)
    server = make_server(args.mode, base, args.port)
    print(f"lab target ({args.mode}) on http://127.0.0.1:{server.server_address[1]}  base={base}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
