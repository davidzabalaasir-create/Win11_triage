"""Análisis estático barato de ejecutables PE con pefile. Solo lee: nunca ejecuta nada."""

from __future__ import annotations

from pathlib import Path

from ..models import Signal

try:
    import pefile
except ImportError:  # pragma: no cover
    pefile = None  # type: ignore[assignment]

PACKER_SECTIONS = {"upx0", "upx1", ".aspack", ".adata", ".themida", ".vmp0", ".vmp1", ".enigma1", ".petite", ".mpress1"}
INJECTION_APIS = {
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtCreateThreadEx",
    "QueueUserAPC",
    "SetThreadContext",
    "NtUnmapViewOfSection",
}
HIGH_ENTROPY = 7.2
YEAR_2100 = 4102444800


def available() -> bool:
    return pefile is not None


def pe_signals(path: Path) -> list[Signal]:
    if pefile is None:
        return []
    try:
        with path.open("rb") as fh:
            if fh.read(2) != b"MZ":
                return []
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    except (pefile.PEFormatError, OSError, ValueError):
        return []
    out: list[Signal] = []
    try:
        names = {s.Name.rstrip(b"\0").decode(errors="ignore").lower() for s in pe.sections}
        packers = names & PACKER_SECTIONS
        if packers:
            out.append(
                Signal(
                    "PE_PACKER_SECTION",
                    "Secciones de empaquetador conocido",
                    25,
                    "T1027.002",
                    ", ".join(sorted(packers)),
                )
            )
        high = [s for s in pe.sections if s.SizeOfRawData > 4096 and s.get_entropy() > HIGH_ENTROPY]
        if high:
            out.append(
                Signal(
                    "PE_HIGH_ENTROPY",
                    "Secciones con entropía muy alta (cifrado/empaquetado)",
                    20,
                    "T1027.002",
                    f"{len(high)} sección(es) > {HIGH_ENTROPY}",
                )
            )
        imports = {
            imp.name.decode(errors="ignore")
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
            for imp in entry.imports
            if imp.name
        }
        inj = imports & INJECTION_APIS
        if len(inj) >= 3:
            out.append(
                Signal(
                    "PE_INJECTION_IMPORTS", "Importa APIs de inyección en procesos", 35, "T1055", ", ".join(sorted(inj))
                )
            )
        if 0 < len(imports) < 5 and high:
            out.append(
                Signal(
                    "PE_FEW_IMPORTS_PACKED",
                    "Muy pocos imports y alta entropía",
                    15,
                    "T1027.002",
                    f"{len(imports)} imports",
                )
            )
        ts = pe.FILE_HEADER.TimeDateStamp
        if ts == 0 or ts > YEAR_2100:
            out.append(Signal("PE_BAD_TIMESTAMP", "Fecha de compilación imposible", 10, "T1070.006", str(ts)))
    finally:
        pe.close()
    return out
