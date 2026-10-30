from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


@pytest.fixture
def example_policy() -> Path:
    return EXAMPLES / "policy.yaml"


@pytest.fixture
def payments_server() -> list[str]:
    return [sys.executable, str(EXAMPLES / "payments_server.py")]
