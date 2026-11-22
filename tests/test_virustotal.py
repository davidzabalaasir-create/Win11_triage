import json
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from win11_triage import virustotal
from win11_triage.virustotal import VTAuthError, VTClient


def _resp(code, malicious=0):
    r = mock.Mock(status_code=code)
    stats = {"malicious": malicious, "suspicious": 0, "undetected": 60}
    r.json.return_value = {"data": {"attributes": {"last_analysis_stats": stats}}}
    return r


@pytest.fixture
def client(tmp_path):
    return VTClient("k", tmp_path / "vt_cache.json", interval=0.2)


def test_cache_dedupes_and_persists(client):
    with mock.patch.object(client.session, "get", side_effect=[_resp(200, 3), _resp(404)]) as get:
        r1 = client.lookup("A" * 64)
        r2 = client.lookup("a" * 64)  # misma clave normalizada → caché
        r3 = client.lookup("b" * 64)
    assert get.call_count == 2
    assert r1["malicious"] == 3 and r1["total"] == 63
    assert r2["cached"] is True
    assert r3["found"] is False
    saved = json.loads(client.cache_file.read_text())
    assert set(saved) == {"a" * 64, "b" * 64}


def test_rate_limit_waits_between_new_requests(client):
    with (
        mock.patch.object(client.session, "get", side_effect=[_resp(404), _resp(404)]),
        mock.patch.object(virustotal.time, "sleep", wraps=virustotal.time.sleep) as sleep,
    ):
        client.lookup("1" * 64)
        sleep.assert_not_called()
        client.lookup("2" * 64)
    assert sleep.called


def test_auth_error_raises(client):
    with mock.patch.object(client.session, "get", return_value=_resp(401)), pytest.raises(VTAuthError):
        client.lookup("c" * 64)


def test_errors_are_not_cached(client):
    with mock.patch.object(client.session, "get", return_value=_resp(500)):
        r = client.lookup("d" * 64)
    assert r == {"error": "HTTP 500"}
    assert client.stats["errors"] == 1
    assert "d" * 64 not in client.cache


def test_not_found_expires_after_ttl(client):
    old = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
    client.cache["e" * 64] = {"found": False, "queried_at": old}
    client.cache["f" * 64] = {"found": True, "malicious": 0, "queried_at": old}
    assert client.cached("e" * 64) is None
    assert client.cached("f" * 64) is not None


def test_corrupt_cache_is_ignored(tmp_path):
    cache = tmp_path / "vt_cache.json"
    cache.write_text("{no json")
    assert VTClient("k", cache).cache == {}


def test_cancel_interrupts_rate_limit_wait(client):
    from win11_triage.models import Cancelled

    client.interval = 30
    with mock.patch.object(client.session, "get", return_value=_resp(404)):
        client.lookup("1" * 64)
        client.cancel.set()
        with pytest.raises(Cancelled):
            client.lookup("2" * 64)


def test_wait_reports_remaining_time(client):
    seen = []
    client.on_wait = seen.append
    with mock.patch.object(client.session, "get", return_value=_resp(404)):
        client.lookup("1" * 64)
        client.lookup("2" * 64)
    assert seen and all(0 < s <= client.interval for s in seen)
