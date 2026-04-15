"""
Generate PWA icon set from a source 512x512 icon.

Usage:
    pip install Pillow
    python scripts/generate_icons.py

Source: static/icons/icon-512.png
Output: static/icons/icon-{size}.png and icon-{size}-maskable.png
"""
import os
import sys
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    print("Pillow is required: pip install Pillow")
    sys.exit(1)

ROOT = Path(__file__).resolve().parent.parent
ICONS_DIR = ROOT / "static" / "icons"
SOURCE = ICONS_DIR / "icon-512.png"

REGULAR_SIZES = [72, 96, 128, 144, 152, 192, 384, 512]
MASKABLE_SIZES = [192, 512]
MASKABLE_BG = (13, 13, 13)  # #0d0d0d
MASKABLE_PADDING = 0.20  # 20% safe zone


def generate_regular(src_img):
    for size in REGULAR_SIZES:
        out = ICONS_DIR / f"icon-{size}.png"
        resized = src_img.resize((size, size), Image.LANCZOS)
        resized.save(out, "PNG", optimize=True)
        print(f"  {out.name}")


def generate_maskable(src_img):
    for size in MASKABLE_SIZES:
        out = ICONS_DIR / f"icon-{size}-maskable.png"
        # Create background with padding
        canvas = Image.new("RGBA", (size, size), (*MASKABLE_BG, 255))
        padding = int(size * MASKABLE_PADDING)
        inner = size - 2 * padding
        icon = src_img.resize((inner, inner), Image.LANCZOS)
        canvas.paste(icon, (padding, padding), icon if icon.mode == "RGBA" else None)
        canvas.save(out, "PNG", optimize=True)
        print(f"  {out.name}")


def main():
    if not SOURCE.exists():
        print(f"Source icon not found: {SOURCE}")
        sys.exit(1)

    src = Image.open(SOURCE).convert("RGBA")
    print(f"Source: {SOURCE} ({src.width}x{src.height})")

    print("\nGenerating regular icons:")
    generate_regular(src)

    print("\nGenerating maskable icons:")
    generate_maskable(src)

    print("\nDone!")


if __name__ == "__main__":
    main()
