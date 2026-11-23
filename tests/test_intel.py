"""Reputación: AbuseIPDB y MalwareBazaar con caché, sin red real."""

from datetime import datetime, timedelta, timezone

from win11_triage import engine, intel
from win11_triage.models import Connection, Finding


def _f(sha="", remote="", cmd=""):
    f = Finding("process", "x.exe", r"C:\x.exe", "", "", sha, cmdline=cmd)
    if remote:
        f.connections.append(Connection("TCP", "x.exe", "1", "ESTABLISHED", "10.0.0.2:5000", remote))
    return f


def test_ip_helpers():
    assert intel.remote_ip("1.2.3.4:443") == "1.2.3.4"
    assert intel.remote_ip("[2001:db8::1]:443") == "2001:db8::1"
    assert not intel.is_public_ip("192.168.1.1") and intel.is_public_ip("8.8.8.8")
    f = _f(cmd="powershell → 8.8.4.4:80")
    assert intel.finding_ips(f) == {"8.8.4.4"}


def test_enrich_signals_and_cache(tmp_path):
    calls = []

    def ip_lookup(ip):
        calls.append(ip)
        return {"score": 90, "reports": 10, "country": "XX", "isp": "Y"}

    def hash_lookup(h):
        calls.append(h)
        return {"found": True, "signature": "Emotet", "tags": ["loader"]}

    cache = intel.IntelCache(tmp_path / "c.json")
    a = _f(sha="a" * 64, remote="8.8.8.8:443")
    b = _f(remote="192.168.1.5:445")
    stats = intel.enrich([a, b], ip_lookup, hash_lookup, cache)
    assert stats["ip_bad"] == 1 and stats["hash_known"] == 1 and stats["network"] == 2
    ids = {s.id for s in a.signals}
    assert {"INTEL_IP_MALICIOUS", "INTEL_MB_KNOWN"} <= ids and not b.signals
    assert a.score >= 70

    # segunda vez: todo desde caché y sin duplicar señales
    stats = intel.enrich([a], ip_lookup, hash_lookup, intel.IntelCache(tmp_path / "c.json"))
    assert stats["cache"] == 2 and len(calls) == 2
    assert sum(s.id.startswith("INTEL_") for s in a.signals) == 2


def test_cache_expiry(tmp_path):
    cache = intel.IntelCache(tmp_path / "c.json")
    cache.put("ip", "8.8.8.8", {"score": 1})
    cache.data["ip"]["8.8.8.8"]["checked"] = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    assert cache.get("ip", "8.8.8.8", intel.IP_TTL) is None


def test_bad_key_disables_service(tmp_path):
    calls = []

    def bad(ip):
        calls.append(ip)
        raise PermissionError("AbuseIPDB rechazó la API key")

    warns = []
    fs = [_f(remote="8.8.8.8:1"), _f(remote="1.1.1.1:1")]
    intel.enrich(fs, bad, None, intel.IntelCache(tmp_path / "c.json"), on_warn=warns.append)
    assert len(calls) == 1 and warns


def test_http_clients_parse(monkeypatch):
    class R:
        def __init__(self, code, body):
            self.status_code, self._b = code, body

        def json(self):
            return self._b

        def raise_for_status(self):
            pass

    class S:
        def get(self, *a, **k):
            assert k["headers"]["Key"] == "k"
            return R(200, {"data": {"abuseConfidenceScore": 77, "totalReports": 4, "countryCode": "RU", "isTor": True}})

        def post(self, *a, **k):
            if k["data"]["hash"] == "none":
                return R(200, {"query_status": "hash_not_found"})
            return R(200, {"query_status": "ok", "data": [{"signature": "Lumma", "tags": ["stealer"]}]})

    ip = intel.abuseipdb_lookup("k", S())("1.2.3.4")
    assert ip["score"] == 77 and ip["tor"]
    mb = intel.malwarebazaar_lookup("k", S())
    assert mb("none") == {"found": False} and mb("x")["signature"] == "Lumma"


def test_engine_dry_run_intel(tmp_path):
    opts = engine.TriageOptions(processes=True, network=True, intel=True, dry_run=True, config_dir=tmp_path)
    res = engine.TriageEngine(opts, {}).run()
    assert "intel" in res.modules and res.intel_stats["ip_bad"] >= 1
    assert any(s.id == "INTEL_IP_MALICIOUS" for f in res.findings for s in f.signals)
    assert not (tmp_path / "intel_cache.json").exists()  # dry-run no persiste
