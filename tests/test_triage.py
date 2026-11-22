"""Pruebas sin red ni Windows: python -m unittest discover tests"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console

from win11_triage import collectors, virustotal
from win11_triage.models import Finding
from win11_triage.whitelist import Whitelist

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


class Parsers(unittest.TestCase):
    def test_autoruns_utf16_and_filter(self):
        raw = (SAMPLES / "autorunsc_sample.csv").read_text(encoding="utf-8").encode("utf-16")
        f = collectors.parse_autoruns(collectors.decode_output(raw))
        names = {x.name for x in f}
        self.assertNotIn("SecurityHealth", names)  # Microsoft verificado → fuera
        self.assertIn("OneSyncHelper", names)      # Not verified → dentro
        self.assertIn("\\UpdaterCheck", names)     # sin firma → dentro
        self.assertTrue(all(len(x.sha256) == 64 for x in f))

    def test_sigcheck(self):
        text = (SAMPLES / "sigcheck_sample.csv").read_text(encoding="utf-8")
        f = collectors.parse_sigcheck(text)
        self.assertEqual(len(f), 3)
        self.assertEqual(f[1].publisher, "Helper Inc")


class WhitelistTest(unittest.TestCase):
    def test_path_and_hash(self):
        wl = Whitelist(paths=["C:\\Tools\\*"], hashes=["ABC"])
        self.assertTrue(wl.matches(Finding("a", "n", "c:\\tools\\x.exe", "", "", "")))
        self.assertTrue(wl.matches(Finding("a", "n", "d:\\y.exe", "", "", "abc")))
        self.assertFalse(wl.matches(Finding("a", "n", "d:\\y.exe", "", "", "def")))


class VTTest(unittest.TestCase):
    def _resp(self, code, malicious=0):
        r = mock.Mock(status_code=code)
        r.json.return_value = {"data": {"attributes": {"last_analysis_stats": {"malicious": malicious, "undetected": 60}}}}
        return r

    def test_cache_and_rate_limit(self):
        with tempfile.TemporaryDirectory() as d:
            cache = Path(d) / "vt_cache.json"
            c = virustotal.VTClient("k", cache, Console(quiet=True), interval=0.3)
            with mock.patch.object(virustotal.requests, "get", side_effect=[self._resp(200, 3), self._resp(404)]) as g, \
                 mock.patch.object(virustotal.time, "sleep", wraps=virustotal.time.sleep) as sl:
                r1 = c.lookup("A" * 64)
                r2 = c.lookup("a" * 64)       # misma clave → caché
                r3 = c.lookup("b" * 64)       # nueva → espera el rate-limit
            self.assertEqual(g.call_count, 2)
            self.assertTrue(sl.called)
            self.assertEqual(r1["malicious"], 3)
            self.assertTrue(r2["cached"])
            self.assertFalse(r3["found"])
            self.assertEqual(set(json.loads(cache.read_text())), {"a" * 64, "b" * 64})


if __name__ == "__main__":
    unittest.main()
