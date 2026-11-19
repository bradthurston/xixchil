#!/usr/bin/env python3
"""Install the mantis as the Android launcher icon.

The painting is landscape and full-bleed, so it is not resized into the icon
slot. The ink is separated from the paper (paper -> transparent), the wash is
cut back so only strokes survive, and the drawing is re-laid out per size.

Two things learned the hard way:
  * Cropping by a hard alpha threshold fails - the dried wash exceeds any
    threshold and spans the whole frame. The crop is taken from where the ink
    actually accumulates (2nd-98th percentile of the column/row mass).
  * At the small densities calligraphic hairlines fall under one pixel and
    turn to dotted mush; the ink is dilated there to keep them alive.
"""
from PIL import Image, ImageFilter, ImageDraw
import numpy as np
import os

RES = "/home/brad/projects/phone-radio-console/app/android/app/src/main/res"
CREAM = (244, 236, 216)          # the painting's own ground, sampled
FLOOR, SPAN = 0.26, 0.45         # alpha curve: high floor kills the wash

# ---- 1. ink, and where it actually is ------------------------------------
src = Image.open("/home/brad/Downloads/xixchil.png").convert("RGB")
a = np.asarray(src.convert("L")).astype(np.float32) / 255.0
paper = np.percentile(a, 92)
ink = 1.0 - np.clip(a / max(paper, 1e-6), 0, 1)
alpha = np.clip((ink - FLOOR) / SPAN, 0, 1)
print("  painting %s   ink covers %.1f%%" % (src.size, (alpha > 0.05).mean() * 100))

col, row = alpha.mean(axis=0), alpha.mean(axis=1)
cs, rs = np.cumsum(col) / col.sum(), np.cumsum(row) / row.sum()
x0, x1 = np.searchsorted(cs, 0.02), np.searchsorted(cs, 0.98)
y0, y1 = np.searchsorted(rs, 0.02), np.searchsorted(rs, 0.98)
pad = 24
box = (max(0, x0-pad), max(0, y0-pad), min(src.size[0], x1+pad), min(src.size[1], y1+pad))
print("  ink mass x %d-%d y %d-%d  ->  crop %s" % (x0, x1, y0, y1, box))

master = Image.merge("RGBA", (*src.split(), Image.fromarray((alpha * 255).astype(np.uint8))))
tight = master.crop(box)
print("  subject %dx%d  aspect %.2f" % (tight.size[0], tight.size[1], tight.size[0] / tight.size[1]))


def layer(size, coverage, dilate=0, solid=False):
    """Ink on transparent, longest side = `coverage` of the tile, centred.

    `solid` throws away the brush texture's partial alpha. Dry ink at 48px
    averages to grey mush, so the small densities get a full-strength
    silhouette instead - the texture is invisible at that size anyway.
    """
    target = max(1, round(size * coverage))
    w, h = tight.size
    if w >= h:
        m = tight.resize((target, max(1, round(h * target / w))), Image.LANCZOS)
    else:
        m = tight.resize((max(1, round(w * target / h)), target), Image.LANCZOS)
    if solid:
        m.putalpha(m.getchannel("A").point(lambda v: 255 if v > 8 else 0))
    if dilate:
        m.putalpha(m.getchannel("A").filter(ImageFilter.MaxFilter(dilate)))
    out = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    out.alpha_composite(m, ((size - m.size[0]) // 2, (size - m.size[1]) // 2))
    return out


def on_cream(size, coverage, circular=False, dilate=0, solid=False):
    bg = Image.new("RGBA", (size, size), (*CREAM, 255))
    if circular:
        big = size * 4
        mask = Image.new("L", (big, big), 0)
        ImageDraw.Draw(mask).ellipse((0, 0, big - 1, big - 1), fill=255)
        bg.putalpha(mask.resize((size, size), Image.LANCZOS))
    comp = Image.alpha_composite(bg, layer(size, coverage, dilate, solid))
    # Keep the alpha for the round variant: converting to RGB silently fills the
    # corners back in with cream and it stops being a circle.
    return comp if circular else comp.convert("RGB")


DENS = [("mdpi", 48, 108), ("hdpi", 72, 162), ("xhdpi", 96, 216),
        ("xxhdpi", 144, 324), ("xxxhdpi", 192, 432)]

for name, L, F in DENS:
    d = os.path.join(RES, "mipmap-" + name)
    # adaptive foreground: 108dp canvas, content kept inside the 72dp safe zone
    layer(F, 0.68).save(os.path.join(d, "ic_launcher_foreground.png"))
    small = L <= 72
    # the drawing is long and low, so the small densities also get to fill more
    sq = 0.95 if small else 0.86
    rd = 0.84 if small else 0.78
    on_cream(L, sq, dilate=3 if small else 0, solid=small).save(os.path.join(d, "ic_launcher.png"))
    on_cream(L, rd, circular=True, dilate=3 if small else 0, solid=small).save(os.path.join(d, "ic_launcher_round.png"))
    print("  %-8s foreground %3dpx @68%%   square %3dpx @%.0f%%%s   round %3dpx @%.0f%%%s"
          % (name, F, L, sq * 100, " solid+dilate" if small else "", L, rd * 100, " solid+dilate" if small else ""))
