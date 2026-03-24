"""
Generate placeholder shield icons for PhishGuard extension.
Run: python generate_icons.py
Creates PNG icons in the icons/ directory.
"""

from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    print("Installing Pillow...")
    import subprocess
    subprocess.check_call(["pip", "install", "Pillow"])
    from PIL import Image, ImageDraw, ImageFont


ICON_DIR = Path(__file__).parent / "icons"
ICON_DIR.mkdir(exist_ok=True)

# Color schemes for each state
SCHEMES = {
    "default": {"bg": "#334155", "shield": "#94a3b8", "accent": "#64748b"},
    "safe":    {"bg": "#065f46", "shield": "#10b981", "accent": "#34d399"},
    "warning": {"bg": "#92400e", "shield": "#f59e0b", "accent": "#fbbf24"},
    "danger":  {"bg": "#991b1b", "shield": "#ef4444", "accent": "#f87171"},
}

SIZES = [16, 32, 48, 128]


def hex_to_rgb(hex_color):
    h = hex_color.lstrip("#")
    return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))


def draw_shield(size, scheme):
    """Draw a simple shield icon."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    bg = hex_to_rgb(scheme["bg"])
    shield_color = hex_to_rgb(scheme["shield"])
    accent = hex_to_rgb(scheme["accent"])

    # Background circle
    padding = max(1, size // 16)
    draw.ellipse(
        [padding, padding, size - padding, size - padding],
        fill=bg + (230,),
    )

    # Shield shape (simplified as a rounded rectangle with pointed bottom)
    s = size
    cx, cy = s // 2, s // 2

    # Shield body
    shield_w = int(s * 0.5)
    shield_h = int(s * 0.55)
    top = int(s * 0.18)
    left = cx - shield_w // 2
    right = cx + shield_w // 2
    bottom = top + shield_h

    # Draw shield as polygon
    points = [
        (left, top + shield_w // 6),           # top-left (rounded)
        (cx, top),                              # top-center
        (right, top + shield_w // 6),           # top-right
        (right, top + int(shield_h * 0.6)),     # right side
        (cx, bottom),                           # bottom point
        (left, top + int(shield_h * 0.6)),      # left side
    ]
    draw.polygon(points, fill=shield_color + (255,))

    # Checkmark or X in center
    mark_size = max(2, size // 6)
    mcx, mcy = cx, cy + max(1, size // 12)

    if scheme == SCHEMES["safe"]:
        # Checkmark
        line_w = max(1, size // 12)
        draw.line(
            [(mcx - mark_size, mcy), (mcx - mark_size // 3, mcy + mark_size // 2)],
            fill=bg + (255,), width=line_w,
        )
        draw.line(
            [(mcx - mark_size // 3, mcy + mark_size // 2), (mcx + mark_size, mcy - mark_size // 2)],
            fill=bg + (255,), width=line_w,
        )
    elif scheme == SCHEMES["danger"]:
        # X mark
        line_w = max(1, size // 12)
        draw.line(
            [(mcx - mark_size // 2, mcy - mark_size // 2),
             (mcx + mark_size // 2, mcy + mark_size // 2)],
            fill=bg + (255,), width=line_w,
        )
        draw.line(
            [(mcx + mark_size // 2, mcy - mark_size // 2),
             (mcx - mark_size // 2, mcy + mark_size // 2)],
            fill=bg + (255,), width=line_w,
        )
    elif scheme == SCHEMES["warning"]:
        # Exclamation mark
        line_w = max(1, size // 10)
        draw.line(
            [(mcx, mcy - mark_size // 2), (mcx, mcy + mark_size // 4)],
            fill=bg + (255,), width=line_w,
        )
        dot_r = max(1, size // 16)
        draw.ellipse(
            [(mcx - dot_r, mcy + mark_size // 2 - dot_r),
             (mcx + dot_r, mcy + mark_size // 2 + dot_r)],
            fill=bg + (255,),
        )

    return img


def main():
    for state, scheme in SCHEMES.items():
        for size in SIZES:
            img = draw_shield(size, scheme)
            filename = f"{state}-{size}.png"
            img.save(ICON_DIR / filename, "PNG")
            print(f"  Created {filename}")

    print(f"\nAll icons saved to {ICON_DIR}/")
    print(f"Total: {len(SCHEMES) * len(SIZES)} icons")


if __name__ == "__main__":
    main()
