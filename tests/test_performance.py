"""Rendimiento: caché de hashes, colectores en paralelo, historial en caché y wevtutil en paralelo."""

import hashlib
import json
import os
import threading
import time

from win11_triage import collectors_events as ce
from win11_triage import hashing, history
from win11_triage.engine import TriageEngine, TriageOptions
from win11_triage.models import Finding


def test_hash_cache_hits_and_invalidation(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"uno")
    cache = hashing.HashCache(tmp_path / "c.json")
    assert cache.sha256(f) == hashlib.sha256(b"uno").hexdigest() and cache.misses == 1
    assert cache.sha256(f) and cache.hits == 1
    cache.save()
    f.write_bytes(b"dos!")  # cambia tamaño y fecha → se recalcula
    os.utime(f, ns=(time.time_ns(), time.time_ns() + 10**9))
    again = hashing.HashCache(tmp_path / "c.json")
    assert again.sha256(f) == hashlib.sha256(b"dos!").hexdigest() and again.misses == 1
    assert again.sha256(tmp_path / "no-existe") == ""


def test_hash_many_parallel(tmp_path):
    paths = []
    for i in range(12):
        p = tmp_path / f"f{i}"
        p.write_bytes(os.urandom(1000))
        paths.append(str(p))
    out = hashing.HashCache().many(paths + paths)  # duplicados: una vez cada uno
    assert len(out) == 12 and all(len(v) == 64 for v in out.values())


def test_collectors_run_in_parallel(tmp_path):
    eng = TriageEngine(TriageOptions(dry_run=True, autoruns=True, config_dir=tmp_path), {})
    active, peak = 0, 0
    lock = threading.Lock()

    def slow(name):
        def fn(_res):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(0.3)
            with lock:
                active -= 1
            return [Finding("autoruns", name, f"C:\\\\{name}.exe", "", "", "")]

        return fn

    jobs = [(f"s{i}", slow(f"n{i}")) for i in range(3)]
    t0 = time.monotonic()
    out = eng._run_collectors(None, jobs)
    assert time.monotonic() - t0 < 0.8 and peak == 3
    assert [s for s, _ in out] == ["s0", "s1", "s2"]  # el orden de las secciones se mantiene


def test_history_cache_reuses_and_refreshes(tmp_path):
    p = tmp_path / "triage_pc_20260101_000000.json"
    data = {"started": "2026-01-01T00:00:00", "host": "pc", "summary": {}, "findings": []}
    p.write_text(json.dumps(data), encoding="utf-8")
    first = history.list_reports(tmp_path)[0]
    assert history.list_reports(tmp_path)[0] is first  # sin cambios: misma entrada
    data["host"] = "otro-equipo"
    p.write_text(json.dumps(data), encoding="utf-8")
    os.utime(p, ns=(time.time_ns(), time.time_ns() + 10**9))
    assert history.list_reports(tmp_path)[0].host == "otro-equipo"


def test_wevtutil_queries_in_parallel(monkeypatch):
    calls = []

    def fake(log, ids, days, max_events=500):
        calls.append(log)
        time.sleep(0.2)
        if "Defender" in log:
            raise RuntimeError("sin acceso")
        return ""

    monkeypatch.setattr(ce, "query_log", fake)
    t0 = time.monotonic()
    findings, warnings = ce.collect_events(7)
    assert time.monotonic() - t0 < 0.5 and len(calls) == len(ce.LOGS)
    assert findings == [] and len(warnings) == 1 and "Defender" in warnings[0]


def test_vt_priority_and_trusted_skip(tmp_path):
    from win11_triage.engine import vt_worthy
    from win11_triage.models import Signal

    signed = Finding("autoruns", "ok", r"C:\ok.exe", "MS", "(Verified) Microsoft", "a" * 64, signed_ok=True)
    assert not vt_worthy(signed)
    signed.add(Signal("X", "x", 40))
    assert vt_worthy(signed)  # firmado pero con señales: sí se consulta
    assert vt_worthy(Finding("autoruns", "x", r"C:\x.exe", "", "", "b" * 64))
    res = TriageEngine(TriageOptions(dry_run=True, autoruns=True, vt=True, vt_all=True, config_dir=tmp_path), {}).run()
    assert res.vt_stats["trusted"] == 0  # --vt-all consulta todo


def test_quick_autoruns_args():
    from win11_triage import collectors

    full, quick = collectors.autoruns_args(), collectors.autoruns_args(quick=True)
    assert full[full.index("-a") + 1] == "*"
    cats = quick[quick.index("-a") + 1]
    assert "l" in cats and "s" in cats and "t" in cats and "c" not in cats and "k" not in cats
