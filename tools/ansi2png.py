#!/usr/bin/env python3
"""
ansi2png — render ANSI (256-color) terminal output to a dark-themed PNG.
Used to generate README screenshots for GhostBuster.

Usage:  ghostbuster +91... | python3 tools/ansi2png.py assets/demo.png
"""
import sys, re
from PIL import Image, ImageDraw, ImageFont

# ── 256-color xterm palette (only the slice we need + generic ramp) ──
def xterm256(n: int):
    if n < 16:
        base = [(0,0,0),(205,0,0),(0,205,0),(205,205,0),(0,0,238),(205,0,205),
                (0,205,205),(229,229,229),(127,127,127),(255,0,0),(0,255,0),
                (255,255,0),(92,92,255),(255,0,255),(0,255,255),(255,255,255)]
        return base[n]
    if n < 232:
        n -= 16
        r, g, b = n // 36, (n % 36) // 6, n % 6
        conv = lambda v: 55 + v * 40 if v else 0
        return (conv(r), conv(g), conv(b))
    v = 8 + (n - 232) * 10
    return (v, v, v)

FG_DEFAULT = (220, 220, 220)
BG = (13, 17, 23)          # GitHub-dark-ish
PAD = 24
LINE_H = 26
CHAR_W = 13
FONT_SIZE = 20

def load_font(bold=False):
    paths = [
        "/usr/share/fonts/truetype/firacode/FiraCode-{}.ttf".format("Bold" if bold else "Regular"),
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono{}.ttf".format("-Bold" if bold else ""),
    ]
    for p in paths:
        try:
            return ImageFont.truetype(p, FONT_SIZE)
        except OSError:
            continue
    return ImageFont.load_default()

FONT = load_font()
FONT_B = load_font(bold=True)

TOKEN = re.compile(r"\x1b\[([0-9;]*)m")

def parse_line(line):
    """Yield (text, fg, bold) runs for one line."""
    runs, pos, fg, bold = [], 0, FG_DEFAULT, False
    for m in TOKEN.finditer(line):
        if m.start() > pos:
            runs.append((line[pos:m.start()], fg, bold))
        codes = [int(c) for c in m.group(1).split(";") if c != ""]
        i = 0
        while i < len(codes):
            c = codes[i]
            if c == 0:
                fg, bold = FG_DEFAULT, False
            elif c == 1:
                bold = True
            elif c == 38 and i + 2 < len(codes) and codes[i+1] == 5:
                fg = xterm256(codes[i+2]); i += 2
            i += 1
        pos = m.end()
    if pos < len(line):
        runs.append((line[pos:], fg, bold))
    return runs

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "demo.png"
    raw = sys.stdin.read().rstrip("\n").split("\n")
    # strip trailing blank lines
    while raw and raw[-1].strip() == "":
        raw.pop()

    width_chars = max((len(TOKEN.sub("", l)) for l in raw), default=80)
    W = PAD * 2 + width_chars * CHAR_W
    H = PAD * 2 + len(raw) * LINE_H + 40  # +title bar

    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    # macOS-style title bar dots
    for i, col in enumerate([(255,95,86),(255,189,46),(39,201,63)]):
        d.ellipse([PAD + i*22, 14, PAD + i*22 + 12, 26], fill=col)
    y0 = 40

    for row, line in enumerate(raw):
        y = y0 + PAD + row * LINE_H
        x = PAD
        for text, fg, bold in parse_line(line):
            d.text((x, y), text, font=(FONT_B if bold else FONT), fill=fg)
            x += len(text) * CHAR_W

    img.save(out)
    print(f"✔ saved {out}  ({W}x{H})")

if __name__ == "__main__":
    main()
