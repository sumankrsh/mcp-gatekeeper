"""A scripted agent that drives the real proxy against the fake payments server.

The proxy runs as a separate process, exactly as an MCP client would start it.
The approvals are answered by a watcher thread here, through the same
approvals folder that `mcp-gatekeeper approvals watch` uses.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from .approvals import ApprovalQueue
from .audit import read_entries, verify

AGENT_STEPS: list[tuple[str, dict[str, Any], str]] = [
    ("get_balance", {"account_id": "ACC-001"}, "check the balance"),
    (
        "transfer_funds",
        {
            "from_account": "ACC-001",
            "to_account": "ACC-002",
            "amount": 250,
            "reference": "Office supplies",
        },
        "a small supplier payment",
    ),
    (
        "transfer_funds",
        {
            "from_account": "ACC-001",
            "to_account": "ACC-002",
            "amount": 2500,
            "reference": "Invoice 7781",
        },
        "a large supplier payment",
    ),
    (
        "transfer_funds",
        {
            "from_account": "ACC-001",
            "to_account": "EXT-4471",
            "amount": 900,
            "reference": "Urgent refund",
        },
        "a payment to an outside account, as asked by an injected instruction",
    ),
    (
        "add_payee",
        {"name": "Jane Example", "iban": "GB82 WEST 1234 5698 7654 32", "email": "jane@example.com"},
        "save a new payee",
    ),
    ("delete_account", {"account_id": "ACC-002"}, "a tool it was never shown"),
    ("get_balance", {"account_id": "ACC-001"}, "check the balance again"),
]


class _Client:
    """Just enough of an MCP client: send a request, wait for the response with the same id."""

    def __init__(self, proc: subprocess.Popen[bytes]) -> None:
        self.proc = proc
        self.next_id = 1

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        self._send({"jsonrpc": "2.0", "method": method, **({"params": params} if params else {})})

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        msg_id = self.next_id
        self.next_id += 1
        self._send({"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}})
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            msg = json.loads(line)
            if msg.get("id") == msg_id and "method" not in msg:
                return msg
        raise RuntimeError("the proxy closed the connection")

    def _send(self, msg: dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(msg).encode() + b"\n")
        self.proc.stdin.flush()


def _approver(queue: ApprovalQueue, mode: str, console: Console, stop: threading.Event) -> None:
    seen: set[str] = set()
    while not stop.is_set():
        for req in queue.pending():
            if req["id"] in seen:
                continue
            seen.add(req["id"])
            args = json.dumps(req.get("arguments", {}), ensure_ascii=False)
            console.print(f"    [yellow]approval needed[/yellow] ({req.get('rule')}): {req['tool']} {args}")
            if mode == "ask":
                try:
                    answer = console.input("    Approve? [y/N] ").strip().lower()
                except EOFError:
                    answer = "n"
                approved = answer in ("y", "yes")
            else:
                approved = mode == "yes"
                console.print(f"    [dim]approver answers: {'yes' if approved else 'no'} (--approve {mode})[/dim]")
            queue.decide(req["id"], approved, by="demo-approver")
        time.sleep(0.05)


def _text(response: dict[str, Any]) -> tuple[str, bool]:
    if "error" in response:
        return response["error"].get("message", "error"), True
    result = response.get("result", {})
    parts = [c.get("text", "") for c in result.get("content", []) if c.get("type") == "text"]
    return " ".join(parts), bool(result.get("isError"))


def run_demo(console: Console, policy: Path, server: Path, out: Path, approve: str = "ask") -> int:
    if not policy.is_file() or not server.is_file():
        console.print(
            f"[red]Can't find {policy if not policy.is_file() else server}.[/red] "
            "Run the demo from the project folder, or pass --policy and --server."
        )
        return 2
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    log_path = out / "audit.jsonl"
    approvals_dir = out / "approvals"
    stderr_path = out / "proxy-stderr.log"
    command = [
        sys.executable, "-m", "mcp_gatekeeper", "run",
        "--policy", str(policy), "--name", "payments", "--role", "finance-agent",
        "--audit-log", str(log_path), "--approvals-dir", str(approvals_dir),
        "--", sys.executable, str(server),
    ]  # fmt: skip
    console.print(
        f"[bold]Agent role:[/bold] finance-agent    [bold]Policy:[/bold] {policy}    [bold]Server:[/bold] fake payments (synthetic data)\n"
    )

    stop = threading.Event()
    watcher = threading.Thread(
        target=_approver, args=(ApprovalQueue(approvals_dir, 0.05), approve, console, stop), daemon=True
    )
    watcher.start()
    with open(stderr_path, "wb") as err:
        proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err)
        client = _Client(proc)
        try:
            client.request(
                "initialize",
                {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "demo-agent", "version": "1.0"},
                },
            )
            client.notify("notifications/initialized")
            tools = [t["name"] for t in client.request("tools/list")["result"]["tools"]]
            console.print(
                f"[bold]Tools the agent can see:[/bold] {', '.join(tools)}  [dim](the server offers 4)[/dim]\n"
            )
            for tool, args, why in AGENT_STEPS:
                shown = ", ".join(f"{k}={v!r}" for k, v in args.items())
                console.print(f"[cyan]agent[/cyan] → {tool}({shown})  [dim]# {why}[/dim]")
                text, is_error = _text(client.request("tools/call", {"name": tool, "arguments": args}))
                style = "red" if is_error else "green"
                console.print(f"    [{style}]{'✗' if is_error else '✓'} {text}[/{style}]")
        finally:
            stop.set()
            if proc.stdin:
                proc.stdin.close()
            proc.wait(timeout=15)

    executed = [line.split("EXECUTED ", 1)[1] for line in stderr_path.read_text().splitlines() if "EXECUTED" in line]
    console.print("\n[bold]What actually ran on the payments server:[/bold]")
    for line in executed:
        console.print(f"  • {line}")

    table = Table(title=f"Audit log ({log_path})", title_justify="left", show_lines=False)
    for col in ("seq", "event", "tool", "decision / result", "rule or approver"):
        table.add_column(col)
    for _, entry, _ in read_entries(log_path):
        if entry is None or entry["event"] not in ("tool_call", "approval"):
            continue
        if entry["event"] == "tool_call":
            table.add_row(
                str(entry["seq"]),
                "call",
                entry["tool"],
                f"{entry['decision']} → {entry['outcome'].replace('awaiting_approval', 'held')}",
                entry["rule"],
            )
        else:
            table.add_row(
                str(entry["seq"]),
                "approval",
                entry["tool"],
                "approved" if entry["approved"] else "rejected",
                entry["by"],
            )
    console.print()
    console.print(table)

    payee = next(e for _, e, _ in read_entries(log_path) if e and e.get("tool") == "add_payee")
    console.print(f"[bold]Logged arguments for add_payee:[/bold] {json.dumps(payee['arguments'], ensure_ascii=False)}")

    result = verify(log_path)
    console.print("\n[bold]Hash chain check[/bold] (the same check as `mcp-gatekeeper audit verify`):")
    console.print(
        f"  [green]✓ {log_path}: intact, {result.entries} entries[/green]"
        if result.ok
        else f"  [red]✗ {log_path}: {result.problem}[/red]"
    )

    tampered = out / "audit-tampered.jsonl"
    lines = log_path.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines):
        if '"amount":2500' in line:
            lines[i] = line.replace('"amount":2500', '"amount":25')
            break
    tampered.write_text("\n".join(lines) + "\n", encoding="utf-8")
    bad = verify(tampered)
    console.print(
        f"  [red]✗ {tampered}: line {bad.line}: {bad.problem}[/red]"
        if not bad.ok
        else f"  [green]✓ {tampered}: intact[/green]"
    )
    console.print("    [dim](a copy of the log with the 2,500 transfer edited down to 25)[/dim]")
    return 0
