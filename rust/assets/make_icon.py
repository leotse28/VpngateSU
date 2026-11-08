#!/usr/bin/env python3
"""Generate assets/icon.ico for the vpngate client (both binaries share it).

Design (v3.15, Leo's call 2026-11-08 — replaces the v3.14 shield,
see icon-candidates/DESIGN_NOTES.md §7): rounded-square tile,
SOLID indigo #1E40AF (no gradient), one single white ring — a
circle outline, no fill, no inner symbol, no second element. The
ring is a bold "O": outer diameter 0.656S, stroke 0.180S, inner
hole 0.297S. At 16x16 the ring is still a real ring (3 px stroke,
4 px hole), not a dot or a hairline — the stroke is deliberately
thicker, in relative terms, than the v3.14 shield's, because a
ring only reads as a ring when the hole stays open.

Sizes: 16/24/32/48/256 — each a NATIVE png (the 24/32/48/256 px
images are rendered from the vector master at 4x supersampling and
downscaled; the 16 px image is a hand-drawn pixel map, NOT a
downscale of the 256 px master — that downscale is exactly what
made the v3.13 tray icon unreadable). The .ico is packed by hand
(struct, no Pillow .ico writer) so each size keeps its own native
PNG entry; Pillow's .ico writer would resample everything from one
image.

Run:  python3 assets/make_icon.py
Out:   assets/icon.ico  (16/24/32/48/256 native PNGs) and assets/icon-256.png (preview),
       plus icon-preview-16/32/48.png next to this script's parent dir
       (the repo root) for a side-by-side check against the old icon
       (icon-preview-old-*.png are kept as the v3.13 reference).

The .ico is a generated binary: it is gitignored, NOT committed to the
repo (the snapshot push only takes text). The script is the source of
truth; build.rs embeds the .ico when it exists and warns otherwise.
"""

import os
import struct

from PIL import Image, ImageDraw

INDIGO = (30, 64, 175, 255)  # #1E40AF, same as the UI selection colour
WHITE = (255, 255, 255, 255)

# Ring master geometry, in 256 px coordinates (centre 128, 128):
#   outer radius 84  -> outer diameter 168 = 0.656S (Leo's band: 62-68%)
#   inner radius 38  -> inner diameter  76 = 0.297S (the hole)
#   stroke 84 - 38 = 46 px = 0.180S (3 px at 16 px, 4 px at 24 px)
R_OUTER_256 = 84
R_INNER_256 = 38


def draw_ring_vector(size):
    """Render the ring at `size` px from the vector master.

    Drawn at 4x and downscaled with LANCZOS (the candidate稿's
    "母稿超采样渲染"), so edges are antialiased rather than jagged.
    The ring is a white disc with an indigo disc cut out of it —
    one element, no extra symbol.
    """
    ss = 4
    big = size * ss
    img = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    tile = Image.new("RGBA", (big, big), INDIGO)
    mask = Image.new("L", (big, big), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        [0, 0, big - 1, big - 1], radius=int(round(0.21 * big)), fill=255
    )
    img.paste(tile, (0, 0), mask)
    d = ImageDraw.Draw(img)
    f = big / 256.0
    cx = cy = big / 2
    ro = R_OUTER_256 * f
    ri = R_INNER_256 * f
    d.ellipse([cx - ro, cy - ro, cx + ro, cy + ro], fill=WHITE)
    d.ellipse([cx - ri, cy - ri, cx + ri, cy + ri], fill=INDIGO)
    return img.resize((size, size), Image.LANCZOS)


# 16 px hand-drawn pixel map, copied verbatim from
# icon-candidates/ring/icon-16.png (the design稿's pixel稿):
# 'W' = white ring stroke, '.' = indigo tile/hole, ' ' = transparent
# (rounded tile corners). Derived from the vector master (white
# coverage >= 0.5 per pixel, measured against a 16x-supersampled
# render: MAE 0.043, 0 hard disagreements — see
# icon-compare-v315.txt): outer diameter 10 px (0.625S, inside
# Leo's 62–68% band), stroke 3 px on every side, hole 4 px across,
# top/bottom of the ring at rows 3/12. The 3 px stroke is the point:
# a 2 px ring at 16 px reads as a hairline, a 1 px one as a dot.
RING_16 = [
    "  ............  ",
    " .............. ",
    "................",
    ".....WWWWWW.....",
    "....WWWWWWWW....",
    "...WWWWWWWWWW...",
    "...WWW....WWW...",
    "...WWW....WWW...",
    "...WWW....WWW...",
    "...WWW....WWW...",
    "...WWWWWWWWWW...",
    "....WWWWWWWW....",
    ".....WWWWWW.....",
    "................",
    " .............. ",
    "  ............  ",
]


def draw_ring_16():
    img = Image.new("RGBA", (16, 16), (0, 0, 0, 0))
    px = img.load()
    for y, row in enumerate(RING_16):
        assert len(row) == 16, f"ring-16 row {y} is {len(row)} px, not 16"
        for x, ch in enumerate(row):
            if ch == "W":
                px[x, y] = WHITE
            elif ch == ".":
                px[x, y] = INDIGO
            elif ch == " ":
                pass
            else:  # pragma: no cover - guarded by the assert above
                raise ValueError(f"bad pixel {ch!r} at ({x}, {y})")
    return img


def draw_ring(size):
    if size == 16:
        return draw_ring_16()
    return draw_ring_vector(size)


def pack_ico(pngs):
    """Pack {size: png_bytes} into .ico bytes (PNG entries).

    Header: reserved(0) + type(1) + count; per entry: width byte
    (0 means 256), height byte, colour count 0, reserved 0, planes 1,
    bit count 32, byte size (u32 LE), offset (u32 LE); then the PNG
    payloads in size order.
    """
    sizes = sorted(pngs)
    header = struct.pack("<HHH", 0, 1, len(sizes))
    entries = b""
    offset = 6 + 16 * len(sizes)
    payloads = b""
    for s in sizes:
        data = pngs[s]
        w = 0 if s == 256 else s
        entries += struct.pack(
            "<BBBBHHII", w, w, 0, 0, 1, 32, len(data), offset
        )
        payloads += data
        offset += len(data)
    return header + entries + payloads


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    images = {s: draw_ring(s) for s in (16, 24, 32, 48, 256)}
    # icon-256.png preview (the master render).
    images[256].save(os.path.join(here, "icon-256.png"))
    # .ico with one native PNG entry per size.
    import io

    pngs = {}
    for s, im in images.items():
        buf = io.BytesIO()
        im.save(buf, format="PNG")
        pngs[s] = buf.getvalue()
    with open(os.path.join(here, "icon.ico"), "wb") as f:
        f.write(pack_ico(pngs))
    # Downscaled previews are the ACTUAL per-size images (not a
    # downscale of the 256 px master), for the readability check.
    for s in (16, 32, 48):
        images[s].save(os.path.join(root, f"icon-preview-{s}.png"))
    print("wrote icon.ico (16/24/32/48/256 native PNGs), icon-256.png, icon-preview-16/32/48.png")


if __name__ == "__main__":
    main()
