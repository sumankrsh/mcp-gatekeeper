"""Record real CLI output into docs/demo.svg.

Run from the project root:  python scripts/make_demo.py

It runs `mcp-gatekeeper demo --approve yes` (the approvals are answered
automatically so the recording doesn't wait on a keyboard) and saves what the
terminal showed.
"""

from __future__ import annotations

import io
import os
import shlex
import shutil
from pathlib import Path

from rich.console import Console
from typer.testing import CliRunner

from mcp_gatekeeper import cli

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    console = Console(record=True, width=112, file=io.StringIO(), force_terminal=True)
    cli.console = console
    os.chdir(ROOT)
    command = "mcp-gatekeeper demo --approve yes"
    console.print(f"[bold green]$[/bold green] [bold]{command}[/bold]")
    result = CliRunner().invoke(cli.app, shlex.split(command)[1:])
    if result.exit_code != 0:
        raise SystemExit(result.output)
    shutil.rmtree(ROOT / "mcp-gatekeeper-demo", ignore_errors=True)
    (ROOT / "docs").mkdir(exist_ok=True)
    console.save_svg(str(ROOT / "docs" / "demo.svg"), title="mcp-gatekeeper")
    print("wrote docs/demo.svg")


if __name__ == "__main__":
    main()
