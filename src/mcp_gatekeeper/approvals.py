"""Human approval for risky calls, through a folder of small JSON files.

The proxy's stdin and stdout belong to the MCP client, so it can't prompt
there. Instead it writes `<id>.request.json` into the approvals folder and
waits. A person answers from any terminal with `mcp-gatekeeper approvals watch`
(or `approve <id>` / `deny <id>`), which writes `<id>.decision.json`. No answer
before the policy's `approval_timeout` means the call is denied.
"""

from __future__ import annotations

import getpass
import json
import os
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DIR_ENV = "MCP_GATEKEEPER_APPROVALS_DIR"
DEFAULT_DIR = ".mcp-gatekeeper/approvals"


@dataclass
class ApprovalResult:
    approved: bool
    by: str
    note: str = ""
    timed_out: bool = False


def current_user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # no login name in some containers
        return "unknown"


def default_dir() -> Path:
    return Path(os.environ.get(DIR_ENV, DEFAULT_DIR))


def _write_atomic(path: Path, data: dict[str, Any]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


class ApprovalQueue:
    def __init__(self, folder: str | Path | None = None, poll_interval: float = 0.2) -> None:
        self.folder = Path(folder) if folder is not None else default_dir()
        self.poll_interval = poll_interval

    def _request_path(self, request_id: str) -> Path:
        return self.folder / f"{request_id}.request.json"

    def _decision_path(self, request_id: str) -> Path:
        return self.folder / f"{request_id}.decision.json"

    # -- proxy side --------------------------------------------------------

    def submit(self, details: dict[str, Any], timeout: float) -> str:
        self.folder.mkdir(parents=True, exist_ok=True)
        request_id = secrets.token_hex(4)
        now = time.time()
        _write_atomic(
            self._request_path(request_id),
            {
                "id": request_id,
                "created": datetime.fromtimestamp(now, UTC).isoformat(timespec="seconds"),
                "expires_at": now + timeout,
                **details,
            },
        )
        return request_id

    def wait(self, request_id: str, timeout: float, cancelled: Callable[[], bool] = lambda: False) -> ApprovalResult:
        deadline = time.monotonic() + timeout
        decision_path = self._decision_path(request_id)
        try:
            while time.monotonic() < deadline and not cancelled():
                if decision_path.exists():
                    try:
                        data = json.loads(decision_path.read_text(encoding="utf-8"))
                    except (OSError, json.JSONDecodeError):
                        time.sleep(self.poll_interval)
                        continue
                    return ApprovalResult(
                        data.get("decision") == "approve", str(data.get("by", "unknown")), str(data.get("note", ""))
                    )
                time.sleep(self.poll_interval)
            return ApprovalResult(False, "timeout" if not cancelled() else "client", timed_out=not cancelled())
        finally:
            for p in (self._request_path(request_id), decision_path):
                p.unlink(missing_ok=True)

    # -- approver side -----------------------------------------------------

    def pending(self) -> list[dict[str, Any]]:
        if not self.folder.is_dir():
            return []
        items = []
        now = time.time()
        for p in sorted(self.folder.glob("*.request.json")):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if self._decision_path(data.get("id", "")).exists() or data.get("expires_at", 0) < now:
                continue
            items.append(data)
        return sorted(items, key=lambda d: d.get("created", ""))

    def decide(self, request_id: str, approve: bool, by: str | None = None, note: str = "") -> None:
        if not self._request_path(request_id).exists():
            raise KeyError(request_id)
        _write_atomic(
            self._decision_path(request_id),
            {"decision": "approve" if approve else "deny", "by": by or current_user(), "note": note},
        )
