"""Genera packaging/version_info.txt (metadatos del .exe: Propiedades → Detalles en Windows)."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
version = re.search(r'__version__ = "([^"]+)"', (ROOT / "win11_triage" / "__init__.py").read_text()).group(1)
nums = [int(x) for x in re.findall(r"\d+", version)[:3]]
tup = tuple([*nums, 0, 0, 0, 0][:4])

TEMPLATE = f"""# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(filevers={tup}, prodvers={tup}, mask=0x3f, flags=0x0, OS=0x40004,
                    fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('0C0A04B0', [
      StringStruct('CompanyName', 'David'),
      StringStruct('FileDescription', 'win11-triage - triaje defensivo de Windows'),
      StringStruct('FileVersion', '{version}'),
      StringStruct('InternalName', 'win11-triage'),
      StringStruct('LegalCopyright', '© 2026 David. Licencia MIT.'),
      StringStruct('OriginalFilename', 'win11-triage.exe'),
      StringStruct('ProductName', 'win11-triage'),
      StringStruct('ProductVersion', '{version}')])]),
    VarFileInfo([VarStruct('Translation', [0x0C0A, 1200])])
  ]
)
"""

if __name__ == "__main__":
    out = ROOT / "packaging" / "version_info.txt"
    out.write_text(TEMPLATE, encoding="utf-8")
    print(f"{out} ({version})")
