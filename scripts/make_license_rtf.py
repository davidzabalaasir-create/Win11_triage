"""Genera packaging/LICENSE.rtf (texto de licencia que muestra el asistente del MSI)."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def rtf_escape(text: str) -> str:
    out = []
    for ch in text:
        if ch in "\\{}":
            out.append("\\" + ch)
        elif ord(ch) > 127:
            out.append(f"\\u{ord(ch)}?")
        else:
            out.append(ch)
    return "".join(out)


if __name__ == "__main__":
    lines = (ROOT / "LICENSE").read_text(encoding="utf-8").splitlines()
    body = "\\par\n".join(rtf_escape(line) for line in lines)
    rtf = "{\\rtf1\\ansi\\ansicpg1252\\deff0{\\fonttbl{\\f0 Segoe UI;}}\\f0\\fs18\n" + body + "\\par\n}"
    out = ROOT / "packaging" / "LICENSE.rtf"
    out.write_text(rtf, encoding="ascii")
    print(out)
