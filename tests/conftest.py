from pathlib import Path

import pytest

from win11_triage import collectors

SAMPLES = Path(__file__).resolve().parent.parent / "win11_triage" / "samples"


@pytest.fixture
def samples() -> Path:
    return SAMPLES


@pytest.fixture
def autoruns_findings(samples):
    raw = (samples / "autorunsc_sample.csv").read_text(encoding="utf-8").encode("utf-16")
    return collectors.parse_autoruns(collectors.decode_output(raw))


@pytest.fixture
def sigcheck_findings(samples):
    return collectors.parse_sigcheck((samples / "sigcheck_sample.csv").read_text(encoding="utf-8"))
