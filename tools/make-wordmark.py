#!/usr/bin/env python3
"""Build the Xixchil wordmark as inline SVG outlines, with a hanko seal.

Vector outlines rather than a shipped font file: 7 glyphs out of a 7.7 MB CJK
face is absurd to bundle, the result cannot be overridden by a fallback font,
and it stays crisp at any density.

Two geometry traps, both handled below:
  * The vertical extent comes from the UNION of the glyph outlines, not from cap
    height -- the ascenders on h and l rise above cap height, so sizing off the
    X alone clips them.
  * A rotated square reaches further than its own edge length; the seal's
    rotation increases the mark's bounding box, so the viewBox is derived from
    the rotated half-diagonal, not from SEAL.

The seal is rotated a few degrees and carries incised strokes. An upright empty
square reads as a tofu/missing-glyph box at header size; a stamped angle plus
carving reads as a seal. The outlines are IPA licensed -- see
fonts/LICENSE-IPA.txt -- separately from the MIT covering the rest of the repo.

glyph tuple: (x_offset, path_data, x0, y0, x1, y1) in font units
"""
from fontTools.ttLib import TTFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.boundsPen import BoundsPen
import subprocess

SRC        = subprocess.run(["fc-match", "-f", "%{file}", "IPAPMincho"],
                            capture_output=True, text=True).stdout.strip()
TEXT       = "Xixchil"
TARGET_CAP = 14.0      # cap height in final SVG units
TRACKING   = 0.0
PAD        = 0.5

ACCENT   = "var(--accent)"   # theme-aware: 朱 in ink, 弁柄 in paper
INK      = "var(--bg)"       # carve is a true knockout, so it must track the ground
SEAL     = 7.0         # seal edge length
SEAL_GAP = 5.6         # gap between the last glyph and the seal
SEAL_ROT = -7          # degrees; straight reads as a box, not a stamp

font    = TTFont(SRC)
glyfset = font.getGlyphSet()
cmap    = font.getBestCmap()
hmtx    = font["hmtx"]

def bounds(gname):
    bp = BoundsPen(glyfset)
    glyfset[gname].draw(bp)
    return bp.bounds

cap_height = bounds(cmap[ord("X")])[3]

glyphs, x_cursor = [], 0.0
for ch in TEXT:
    g = cmap[ord(ch)]
    pen = SVGPathPen(glyfset)
    glyfset[g].draw(pen)
    b = bounds(g)
    if b:
        x0, y0, x1, y1 = b
        glyphs.append((x_cursor, pen.getCommands(), x0, y0, x1, y1))
    x_cursor += hmtx[g][0] + TRACKING

scale = TARGET_CAP / cap_height
ink_top    = max(g[5] for g in glyphs)                 # y1
ink_bottom = min(g[3] for g in glyphs)                 # y0
ink_right  = max(g[0] + g[4] for g in glyphs)          # x_offset + x1

baseline     = ink_top * scale + PAD
glyph_bottom = baseline - ink_bottom * scale           # ink_bottom is negative
glyph_right  = ink_right * scale + PAD

# ── seal placement, then the viewBox from the union of ink and rotated seal ──
seal_x   = glyph_right + SEAL_GAP
seal_cx  = seal_x + SEAL / 2
seal_cy  = baseline - SEAL / 2
halfdiag = (SEAL * (2 ** 0.5)) / 2

width  = max(glyph_right, seal_cx + halfdiag) + PAD
height = max(glyph_bottom, seal_cy + halfdiag) + PAD

def seal_mark():
    carve = (
        '<rect x="-2.1" y="-2.6" width="4.2" height="1.05" fill="%s"/>'
        '<rect x="-2.1" y="0.5" width="4.2" height="1.05" fill="%s"/>' % (INK, INK)
    )
    return (f'<g transform="rotate({SEAL_ROT} {seal_cx:.3f} {seal_cy:.3f})">'
            f'<rect x="{seal_x:.3f}" y="{baseline - SEAL:.3f}" width="{SEAL}" height="{SEAL}" '
            f'rx="1.0" fill="{ACCENT}"/>'
            f'<g transform="translate({seal_cx:.3f} {seal_cy:.3f})">{carve}</g></g>')

paths = [
    f'<path transform="translate({g[0]*scale:.3f},{baseline:.3f}) '
    f'scale({scale:.6f},{-scale:.6f})" d="{g[1]}"/>'
    for g in glyphs if g[1]
]

svg = (f'<svg class="wordmark" viewBox="0 0 {width:.2f} {height:.2f}" '
       f'width="{width:.2f}" height="{height:.2f}" role="img" aria-label="Xixchil" '
       f'focusable="false">' + "".join(paths) + seal_mark() + "</svg>")

open("/tmp/wordmark.svg", "w").write(svg)
print(f"  source       {SRC}  (upm {font['head'].unitsPerEm})")
print(f"  cap height   {cap_height}   ink top {ink_top}   ink bottom {ink_bottom}")
print(f"  scale        {scale:.6f}   baseline {baseline:.3f}")
print(f"  seal         {SEAL}px @ {SEAL_ROT}deg  centre ({seal_cx:.2f},{seal_cy:.2f})  halfdiag {halfdiag:.2f}")
print(f"  viewBox      0 0 {width:.2f} {height:.2f}   ({len(svg)} bytes)")
