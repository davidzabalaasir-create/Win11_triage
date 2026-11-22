import os
import struct

import pytest

from win11_triage.enrich import eligible, file_of, pe_static, yara_scan
from win11_triage.models import Finding


def make_pe(path, section=b"UPX0", timestamp=0):
    """PE32 mínimo y válido para pefile: 1 sección de datos aleatorios (alta entropía)."""
    raw = os.urandom(0x2000)
    dos = b"MZ" + b"\0" * 58 + struct.pack("<I", 0x40)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, timestamp, 0, 0, 0xE0, 0x0102)
    opt = (
        struct.pack(
            "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
            0x10B,
            14,
            0,
            0x2000,
            0,
            0,
            0x1000,
            0x1000,
            0x1000,
            0x400000,
            0x1000,
            0x200,
            6,
            0,
            0,
            0,
            6,
            0,
            0,
            0x3000,
            0x200,
            0,
            2,
            0,
            0x100000,
            0x1000,
            0x100000,
            0x1000,
            0,
            16,
        )
        + b"\0" * 128
    )
    sect = section.ljust(8, b"\0") + struct.pack("<IIIIIIHHI", 0x2000, 0x1000, 0x2000, 0x200, 0, 0, 0, 0, 0x60000020)
    header = (dos + b"PE\0\0" + coff + opt + sect).ljust(0x200, b"\0")
    path.write_bytes(header + raw)
    return path


@pytest.mark.skipif(not pe_static.available(), reason="pefile no instalado")
def test_pe_signals_on_synthetic_packed_pe(tmp_path):
    sigs = {s.id for s in pe_static.pe_signals(make_pe(tmp_path / "a.exe"))}
    assert {"PE_PACKER_SECTION", "PE_HIGH_ENTROPY", "PE_BAD_TIMESTAMP"} <= sigs


@pytest.mark.skipif(not pe_static.available(), reason="pefile no instalado")
def test_pe_signals_ignore_non_pe(tmp_path):
    p = tmp_path / "x.txt"
    p.write_text("hola")
    assert pe_static.pe_signals(p) == []


def test_eligibility_and_file_resolution(tmp_path):
    p = tmp_path / "a.exe"
    p.write_bytes(b"MZ")
    unsigned = Finding("sigcheck", "a", str(p), "", "Unsigned", "")
    assert eligible(unsigned) and file_of(unsigned) == p
    signed = Finding("autoruns", "a", str(p), "", "", "", signed_ok=True)
    assert not eligible(signed)
    assert file_of(Finding("autoruns", "a", "File not found: C:\\x", "", "", "")) is None


@pytest.mark.skipif(not yara_scan.available(), reason="yara-python no instalado")
def test_builtin_yara_rules_compile_and_match(tmp_path):
    (tmp_path / "yara").mkdir()
    (tmp_path / "yara" / "mine.yar").write_text('rule Mine { strings: $a = "marcador-propio" condition: $a }')
    scanner = yara_scan.YaraScanner(tmp_path / "yara")
    script = tmp_path / "a.ps1"
    script.write_text("powershell -nop -w hidden -enc " + "A" * 60 + " marcador-propio")
    got = {s.id: s for s in scanner.scan(script)}
    assert "YARA_W11T_PS_EncodedOrHidden" in got and got["YARA_W11T_PS_EncodedOrHidden"].weight == 40
    assert "YARA_Mine" in got
    benign = tmp_path / "b.ps1"
    benign.write_text("Write-Host 'hola'")
    assert scanner.scan(benign) == []
