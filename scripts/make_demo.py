"""Genera docs/demo.svg a partir de un --dry-run (python scripts/make_demo.py)."""

import tempfile
from pathlib import Path

from rich.console import Console

from win11_triage import cli

ROOT = Path(__file__).resolve().parent.parent

if __name__ == "__main__":
    cli.console = Console(record=True, width=120, force_terminal=True, highlight=False)
    with tempfile.TemporaryDirectory() as tmp:
        cli.run(cli.parse_args(["--dry-run", "--no-report", "--config-dir", tmp]))
    cli.console.save_svg(str(ROOT / "docs" / "demo.svg"), title="win11-triage --dry-run")
    print("docs/demo.svg generado")
