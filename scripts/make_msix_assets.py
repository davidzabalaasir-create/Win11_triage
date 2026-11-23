"""Genera los logotipos del paquete MSIX a partir de win11_triage/assets/icon.png."""

from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "win11_triage" / "assets" / "icon.png"
OUT = ROOT / "packaging" / "msix" / "Assets"
SIZES = {"Square44x44Logo.png": (44, 44), "Square150x150Logo.png": (150, 150), "StoreLogo.png": (50, 50),
         "Wide310x150Logo.png": (310, 150)}  # fmt: skip


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    icon = Image.open(SRC).convert("RGBA")
    for name, (w, h) in SIZES.items():
        side = min(w, h)
        canvas = Image.new("RGBA", (w, h), (0, 0, 0, 0))
        logo = icon.resize((int(side * 0.8), int(side * 0.8)), Image.LANCZOS)
        canvas.paste(logo, ((w - logo.width) // 2, (h - logo.height) // 2), logo)
        canvas.save(OUT / name)
    print(f"Logotipos MSIX en {OUT}")


if __name__ == "__main__":
    main()
