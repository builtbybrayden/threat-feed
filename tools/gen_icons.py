#!/usr/bin/env python3
"""Generate the PWA icons with the standard library only (no Pillow dependency).

Draws a simple "radar target" glyph (concentric ring + crosshair + center dot)
in the brand accent on a dark background. Run:

    python tools/gen_icons.py
"""

from __future__ import annotations

import math
import struct
import zlib
from pathlib import Path

BG = (11, 16, 32)        # #0b1020
ACCENT = (61, 220, 151)  # #3ddc97
SIZES = (180, 192, 512)
OUT = Path(__file__).resolve().parent.parent / "site" / "icons"


def _png(width: int, height: int, pixels: bytes) -> bytes:
    """Encode RGB pixel bytes (width*height*3) as a PNG."""
    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    # Add the mandatory per-scanline filter byte (0 = none).
    raw = bytearray()
    stride = width * 3
    for y in range(height):
        raw.append(0)
        raw.extend(pixels[y * stride : (y + 1) * stride])

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)  # 8-bit RGB
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + chunk(b"IEND", b"")
    )


def _render(size: int) -> bytes:
    cx = cy = (size - 1) / 2
    ring_r = size * 0.33
    ring_w = max(2.0, size * 0.045)
    dot_r = size * 0.07
    cross_half = size * 0.40
    cross_w = max(2.0, size * 0.035)

    buf = bytearray(size * size * 3)
    for y in range(size):
        for x in range(size):
            dx, dy = x - cx, y - cy
            dist = math.hypot(dx, dy)
            color = BG
            # Crosshair arms (leave a gap over the center).
            on_h = abs(dy) <= cross_w / 2 and abs(dx) <= cross_half and dist > dot_r * 1.3
            on_v = abs(dx) <= cross_w / 2 and abs(dy) <= cross_half and dist > dot_r * 1.3
            if on_h or on_v:
                color = ACCENT
            # Concentric ring.
            if abs(dist - ring_r) <= ring_w / 2:
                color = ACCENT
            # Center dot.
            if dist <= dot_r:
                color = ACCENT
            i = (y * size + x) * 3
            buf[i], buf[i + 1], buf[i + 2] = color
    return _png(size, size, bytes(buf))


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for size in SIZES:
        path = OUT / f"icon-{size}.png"
        path.write_bytes(_render(size))
        print(f"wrote {path} ({path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
