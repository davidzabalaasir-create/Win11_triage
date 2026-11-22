"""Genera el logo de la app (win11_triage/assets/): escudo con lupa sobre fondo degradado.

python scripts/make_icon.py  (requiere Pillow)
"""

from pathlib import Path

from PIL import Image, ImageChops, ImageDraw, ImageFilter

OUT = Path(__file__).resolve().parent.parent / "win11_triage" / "assets"
S = 1024  # se dibuja grande y se reduce: bordes suaves


def gradient(size: int, top: tuple[int, int, int], bottom: tuple[int, int, int]) -> Image.Image:
    g = Image.new("RGB", (1, size))
    for y in range(size):
        t = y / (size - 1)
        g.putpixel((0, y), tuple(int(a + (b - a) * t) for a, b in zip(top, bottom, strict=True)))
    return g.resize((size, size))


def rounded_mask(size: int, radius: int) -> Image.Image:
    m = Image.new("L", (size, size), 0)
    ImageDraw.Draw(m).rounded_rectangle((0, 0, size - 1, size - 1), radius, fill=255)
    return m


def shield(draw: ImageDraw.ImageDraw, cx: int, top: int, w: int, h: int, **kw) -> None:
    pts = []
    for i in range(41):  # lados curvos hacia la punta inferior
        t = i / 40
        x = cx - w / 2 + (w / 2) * (t**1.8)
        y = top + h * 0.38 + (h * 0.62) * t
        pts.append((x, y))
    left = [(cx - w / 2, top + h * 0.12), (cx - w * 0.18, top + h * 0.02), (cx, top)]
    right = [(2 * cx - x, y) for x, y in reversed(pts)]
    right_top = [(cx + w * 0.18, top + h * 0.02), (cx + w / 2, top + h * 0.12)]
    poly = [*left, *right_top, (cx + w / 2, top + h * 0.38), *right, *reversed(pts)]
    draw.polygon(poly, **kw)


def make() -> Image.Image:
    bg = gradient(S, (37, 99, 235), (8, 145, 178))  # azul → cian
    # brillo diagonal sutil
    glow = Image.new("L", (S, S), 0)
    ImageDraw.Draw(glow).ellipse((-S * 0.3, -S * 0.5, S * 0.9, S * 0.55), fill=70)
    glow = glow.filter(ImageFilter.GaussianBlur(S // 12))
    bg = Image.composite(Image.new("RGB", (S, S), (255, 255, 255)), bg, glow)

    layer = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    cx, top, w, h = S // 2, int(S * 0.15), int(S * 0.56), int(S * 0.68)
    # sombra del escudo
    sh = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    shield(ImageDraw.Draw(sh), cx, top + 24, w, h, fill=(0, 0, 0, 90))
    sh = sh.filter(ImageFilter.GaussianBlur(28))
    # escudo blanco con interior azul oscuro
    shield(d, cx, top, w, h, fill=(255, 255, 255, 255))
    inner = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    shield(ImageDraw.Draw(inner), cx, top + 44, w - 92, h - 84, fill=(15, 23, 42, 255))
    layer = Image.alpha_composite(layer, inner)
    d = ImageDraw.Draw(layer)
    # lupa
    r = int(S * 0.13)
    mx, my = cx - int(S * 0.03), top + int(h * 0.42)
    d.ellipse((mx - r, my - r, mx + r, my + r), outline=(56, 189, 248, 255), width=int(S * 0.035))
    hx, hy = mx + int(r * 0.72), my + int(r * 0.72)
    d.line((hx, hy, hx + int(r * 0.9), hy + int(r * 0.9)), fill=(56, 189, 248, 255), width=int(S * 0.05))
    # pulso dentro de la lupa
    p = [(-0.75, 0), (-0.3, 0), (-0.12, -0.5), (0.1, 0.45), (0.28, 0), (0.75, 0)]
    d.line([(mx + x * r, my + y * r) for x, y in p], fill=(34, 197, 94, 255), width=int(S * 0.022), joint="curve")

    mask = rounded_mask(S, int(S * 0.22))
    base = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    base.paste(bg, (0, 0), mask)
    base = Image.alpha_composite(base, Image.composite(sh, Image.new("RGBA", (S, S)), mask))
    base = Image.alpha_composite(base, layer)
    a = ImageChops.multiply(base.getchannel("A"), mask)
    base.putalpha(a)
    return base


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    img = make()
    img.resize((256, 256), Image.LANCZOS).save(OUT / "icon.png")
    img.resize((64, 64), Image.LANCZOS).save(OUT / "icon_64.png")
    img.save(OUT / "icon.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    print("Iconos generados en", OUT)
