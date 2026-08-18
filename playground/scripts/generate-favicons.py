#!/usr/bin/env python3
"""Render Defender favicon PNGs and a multi-size ICO from the product mark."""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[1] / "public"
BG = (10, 10, 10, 255)
FG = (250, 250, 250, 255)


def scale_point(x: float, y: float, size: int, pad: float) -> tuple[float, float]:
    inner = size * (1 - 2 * pad)
    return pad * size + x / 32 * inner, pad * size + y / 32 * inner


def draw_mark(size: int, *, pad: float = 0.0, rounded: bool = True) -> Image.Image:
    scale = 8
    canvas = size * scale
    image = Image.new("RGBA", (canvas, canvas), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    def pt(x: float, y: float) -> tuple[float, float]:
        return scale_point(x, y, canvas, pad)

    if rounded:
        radius = canvas * (1 - 2 * pad) * 0.22
        box = (pt(0, 0)[0], pt(0, 0)[1], pt(32, 32)[0] - 1, pt(32, 32)[1] - 1)
        draw.rounded_rectangle(box, radius=radius, fill=BG)
    else:
        draw.rectangle((0, 0, canvas - 1, canvas - 1), fill=BG)

    shield = [
        pt(9.4, 7.8),
        pt(16, 5.6),
        pt(22.6, 7.8),
        pt(22.6, 16.2),
        pt(16, 26.2),
        pt(9.4, 16.2),
    ]
    draw.polygon(shield, fill=FG)

    check = [pt(11.4, 16.3), pt(14.4, 19.3), pt(21.0, 12.6)]
    stroke = max(canvas * 0.055, 6)
    draw.line(check, fill=BG, width=int(stroke), joint="curve")
    return image.resize((size, size), Image.Resampling.LANCZOS)


def save_png(image: Image.Image, name: str) -> None:
    path = ROOT / name
    image.save(path, format="PNG", optimize=True)
    print(f"wrote {path.relative_to(ROOT.parent)}")


def main() -> None:
    ROOT.mkdir(parents=True, exist_ok=True)

    ico_path = ROOT / "favicon.ico"
    draw_mark(256).save(
        ico_path,
        format="ICO",
        sizes=[(16, 16), (32, 32), (48, 48)],
    )
    print(f"wrote {ico_path.relative_to(ROOT.parent)}")

    save_png(draw_mark(16), "favicon-16x16.png")
    save_png(draw_mark(32), "favicon-32x32.png")
    save_png(draw_mark(180, rounded=False), "apple-touch-icon.png")
    save_png(draw_mark(192, rounded=False), "android-chrome-192x192.png")
    save_png(draw_mark(512, rounded=False), "android-chrome-512x512.png")
    save_png(draw_mark(512, pad=0.1, rounded=True), "android-chrome-512x512-maskable.png")


if __name__ == "__main__":
    main()
