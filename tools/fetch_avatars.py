#!/usr/bin/env python3
"""Download real source avatars/logos at build time and commit them locally.

Keeping the images same-origin means the site's strict CSP (img-src 'self')
stays intact — no third-party image hosts at runtime. app.js falls back to
initials for any source whose avatar is missing.

    python tools/fetch_avatars.py
"""

from __future__ import annotations

from pathlib import Path

import requests

OUT = Path(__file__).resolve().parent.parent / "site" / "avatars"

# slug -> ordered candidate URLs (first valid PNG/JPEG wins). GitHub avatars are
# crisp; the Google favicon service is a reliable PNG fallback for any domain.
SOURCES: dict[str, list[str]] = {
    "portswigger": [
        "https://github.com/PortSwigger.png?size=160",
        "https://www.google.com/s2/favicons?domain=portswigger.net&sz=128",
    ],
    "projectzero": [
        "https://github.com/googleprojectzero.png?size=160",
        "https://www.google.com/s2/favicons?domain=googleprojectzero.blogspot.com&sz=128",
    ],
    "ghsecuritylab": [
        "https://github.com/github.png?size=160",
        "https://www.google.com/s2/favicons?domain=securitylab.github.com&sz=128",
    ],
    "tldrsec": [
        "https://github.com/tldrsec.png?size=160",
        "https://www.google.com/s2/favicons?domain=tldrsec.com&sz=128",
    ],
    "riskybiz": [
        "https://www.google.com/s2/favicons?domain=risky.biz&sz=128",
    ],
    "simonw": [
        "https://github.com/simonw.png?size=160",
    ],
}

PNG = b"\x89PNG\r\n\x1a\n"
JPEG = b"\xff\xd8\xff"


def _valid_image(content: bytes) -> bool:
    return len(content) > 400 and (content.startswith(PNG) or content.startswith(JPEG))


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    session = requests.Session()
    session.headers.update({"User-Agent": "threat-feed-avatar-fetch/0.1"})
    for slug, urls in SOURCES.items():
        saved = False
        for url in urls:
            try:
                r = session.get(url, timeout=15, allow_redirects=True)
                if r.status_code == 200 and _valid_image(r.content):
                    (OUT / f"{slug}.png").write_bytes(r.content)
                    print(f"{slug}: {len(r.content)} bytes <- {url}")
                    saved = True
                    break
            except requests.RequestException:
                continue
        if not saved:
            print(f"{slug}: no avatar found (will use initials fallback)")


if __name__ == "__main__":
    main()
