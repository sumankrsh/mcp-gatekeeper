"""Command-line interface."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .approvals import DIR_ENV, ApprovalQueue, current_user, default_dir
from .audit import KEY_ENV, AuditLog, key_from_env, read_entries, verify
from .policy import PolicyError, load_policy

LOG_ENV = "MCP_GATEKEEPER_AUDIT_LOG"
ROLE_ENV = "MCP_GATEKEEPER_ROLE"
DEFAULT_LOG = ".mcp-gatekeeper/audit.jsonl"

app = typer.Typer(
    help="Permissions, approvals and a tamper-evident audit log for MCP tool calls.",
    no_args_is_help=True,
    add_completion=False,
)
audit_app = typer.Typer(help="Check and read the audit log.", no_args_is_help=True)
approvals_app = typer.Typer(help="Answer calls that are waiting for approval.", no_args_is_help=True)
app.add_typer(audit_app, name="audit")
app.add_typer(approvals_app, name="approvals")

console = Console()
err = Console(stderr=True)


def _default_log() -> Path:
    return Path(os.environ.get(LOG_ENV, DEFAULT_LOG))


def _policy_or_exit(path: Path):
    try:
        return load_policy(path)
    except PolicyError as exc:
        err.print(f"[red]Policy error:[/red] {exc}")
        raise typer.Exit(2) from exc


def _version(value: bool) -> None:
    if value:
        console.print(f"mcp-gatekeeper {__version__}")
        raise typer.Exit()


@app.callback()
def main_callback(
    version: Annotated[
        bool, typer.Option("--version", callback=_version, is_eager=True, help="Show the version.")
    ] = False,
) -> None:
    pass


@app.command(context_settings={"allow_interspersed_args": False})
def run(
    command: Annotated[list[str], typer.Argument(help="The MCP server command to wrap, after `--`.")],
    policy: Annotated[Path, typer.Option("--policy", "-p", help="Policy YAML file.")],
    name: Annotated[
        str, typer.Option("--name", "-n", help="Server name used in rules (`payments.*`) and the log.")
    ] = "server",
    role: Annotated[
        str | None, typer.Option("--role", "-r", help=f"Role of the agent using this connection. Env: {ROLE_ENV}.")
    ] = None,
    audit_log: Annotated[
        Path | None, typer.Option("--audit-log", help=f"Audit log file. Env: {LOG_ENV}. Default {DEFAULT_LOG}.")
    ] = None,
    approvals_dir: Annotated[
        Path | None, typer.Option("--approvals-dir", help=f"Approvals folder. Env: {DIR_ENV}.")
    ] = None,
    show_all_tools: Annotated[
        bool, typer.Option("--show-all-tools", help="Don't hide always-denied tools from tools/list.")
    ] = False,
) -> None:
    """Run an MCP server behind the gatekeeper: mcp-gatekeeper run -p policy.yaml -- python server.py"""
    from .proxy import run_stdio

    pol = _policy_or_exit(policy)
    code = run_stdio(
        command,
        pol,
        AuditLog(audit_log or _default_log(), key_from_env()),
        ApprovalQueue(approvals_dir),
        server=name,
        role=role or os.environ.get(ROLE_ENV, "default"),
        hide_denied_tools=not show_all_tools,
    )
    raise typer.Exit(code)


@app.command()
def validate(policy: Annotated[Path, typer.Argument(help="Policy YAML file.")]) -> None:
    """Check a policy file and list its rules in the order they are applied."""
    pol = _policy_or_exit(policy)
    table = Table(title=f"{policy} (first match wins; default: {pol.default})", title_justify="left")
    for col in ("#", "rule", "tools", "roles", "when", "action", "rate limit"):
        table.add_column(col)
    for i, r in enumerate(pol.rules, start=1):
        when = "; ".join(f"{path} {op} {val!r}" for path, conds in r.when.items() for op, val in conds.items())
        rl = f"{r.rate_limit.calls}/{r.rate_limit.per_seconds:g}s" if r.rate_limit else ""
        table.add_row(str(i), r.name, ", ".join(r.tools), ", ".join(r.roles or ["any"]), when, r.action, rl)
    console.print(table)
    console.print(f"[green]✓ valid[/green] ({len(pol.rules)} rules, approval timeout {pol.approval_timeout:g}s)")


@app.command()
def explain(
    policy: Annotated[Path, typer.Argument(help="Policy YAML file.")],
    tool: Annotated[str, typer.Argument(help="Tool name.")],
    args: Annotated[str, typer.Option("--args", "-a", help="Arguments as a JSON object.")] = "{}",
    role: Annotated[str, typer.Option("--role", "-r")] = "default",
    name: Annotated[str | None, typer.Option("--name", "-n", help="Server name.")] = None,
) -> None:
    """Show what the policy would do with one call, without running anything. Exit code 0 allow, 1 deny, 3 approve."""
    pol = _policy_or_exit(policy)
    try:
        arguments = json.loads(args)
    except json.JSONDecodeError as exc:
        err.print(f"[red]--args is not valid JSON:[/red] {exc}")
        raise typer.Exit(2) from exc
    if not isinstance(arguments, dict):
        err.print("[red]--args must be a JSON object[/red]")
        raise typer.Exit(2)
    d = pol.evaluate(tool, arguments, role, name)
    colour = {"allow": "green", "deny": "red", "approve": "yellow"}[d.action]
    console.print(f"[{colour}]{d.action.upper()}[/{colour}] {tool} for role '{role}': {d.reason}")
    raise typer.Exit({"allow": 0, "deny": 1, "approve": 3}[d.action])


@app.command()
def demo(
    approve: Annotated[
        str, typer.Option("--approve", help="ask: prompt you; yes or no: answer every approval automatically.")
    ] = "ask",
    policy: Annotated[Path, typer.Option("--policy", help="Policy for the demo.")] = Path("examples/policy.yaml"),
    server: Annotated[Path, typer.Option("--server", help="The fake payments server.")] = Path(
        "examples/payments_server.py"
    ),
    out: Annotated[Path, typer.Option("--out", help="Folder for the demo's audit log (replaced on each run).")] = Path(
        "mcp-gatekeeper-demo"
    ),
) -> None:
    """Watch an agent's payment calls go through the gatekeeper: allowed, approved, blocked and logged."""
    from .demo import run_demo

    if approve not in ("ask", "yes", "no"):
        err.print("[red]--approve must be ask, yes or no[/red]")
        raise typer.Exit(2)
    raise typer.Exit(run_demo(console, policy, server, out, approve))


# -- audit ------------------------------------------------------------------


@audit_app.command("verify")
def audit_verify(
    log: Annotated[
        Path | None,
        typer.Argument(help=f"Audit log. Default ${LOG_ENV} or {DEFAULT_LOG}. Set {KEY_ENV} for HMAC-signed logs."),
    ] = None,
    expect_head: Annotated[
        str | None, typer.Option("--expect-head", help="A head hash recorded earlier; fails if it's gone.")
    ] = None,
) -> None:
    """Check that no entry was edited, removed or reordered. Exit code 1 if the chain is broken."""
    path = log or _default_log()
    if not path.is_file():
        err.print(f"[red]No audit log at {path}[/red]")
        raise typer.Exit(2)
    result = verify(path, key_from_env(), expect_head)
    if result.ok:
        console.print(f"[green]✓ chain intact:[/green] {result.entries} entries, head {result.head}")
        return
    where = f"line {result.line}: " if result.line else ""
    console.print(f"[red]✗ {where}{result.problem}[/red]")
    console.print(f"  {result.entries} entries checked before the problem.")
    raise typer.Exit(1)


@audit_app.command("show")
def audit_show(
    log: Annotated[Path | None, typer.Argument(help="Audit log.")] = None,
    last: Annotated[int, typer.Option("--last", help="Show only the last N entries (0 for all).")] = 20,
    tool: Annotated[str | None, typer.Option("--tool", help="Only entries for this tool.")] = None,
) -> None:
    """Print audit entries as a table."""
    path = log or _default_log()
    if not path.is_file():
        err.print(f"[red]No audit log at {path}[/red]")
        raise typer.Exit(2)
    rows = [e for _, e, _ in read_entries(path) if e is not None and (tool is None or e.get("tool") == tool)]
    if last:
        rows = rows[-last:]
    table = Table(title=str(path), title_justify="left")
    for col in ("seq", "time (UTC)", "event", "tool", "detail"):
        table.add_column(col)
    for e in rows:
        event = e.get("event", "")
        if event == "tool_call":
            detail = (
                f"{e['decision']} → {e['outcome']} ({e['rule']}) {json.dumps(e.get('arguments'), ensure_ascii=False)}"
            )
        elif event == "approval":
            detail = f"{'approved' if e.get('approved') else 'rejected'} by {e.get('by')}"
        elif event == "tool_result":
            detail = f"{'error' if e.get('is_error') else 'ok'} in {e.get('duration_ms')} ms"
        elif event == "proxy_start":
            detail = f"role {e.get('role')}, policy sha256 {str(e.get('policy_sha256'))[:12]}…"
        else:
            detail = ", ".join(
                f"{k}={v}" for k, v in e.items() if k not in ("seq", "ts", "event", "hash", "prev", "mac")
            )
        table.add_row(
            str(e.get("seq")), str(e.get("ts", ""))[:23].replace("T", " "), event, str(e.get("tool", "")), detail
        )
    console.print(table)


@audit_app.command("head")
def audit_head(log: Annotated[Path | None, typer.Argument(help="Audit log.")] = None) -> None:
    """Print the hash of the newest entry, to store somewhere else and check later with --expect-head."""
    path = log or _default_log()
    result = verify(path, key_from_env()) if path.is_file() else None
    if result is None or not result.ok:
        err.print(f"[red]Cannot read a valid chain from {path}[/red]")
        raise typer.Exit(1)
    console.print(result.head)


# -- approvals --------------------------------------------------------------


def _queue(folder: Path | None) -> ApprovalQueue:
    return ApprovalQueue(folder or default_dir())


DirOption = Annotated[Path | None, typer.Option("--dir", "-d", help=f"Approvals folder. Env: {DIR_ENV}.")]


def _describe(req: dict) -> str:
    args = json.dumps(req.get("arguments", {}), ensure_ascii=False)
    left = max(0, int(req.get("expires_at", 0) - time.time()))
    return f"[bold]{req['id']}[/bold]  {req.get('server')}.{req['tool']} {args}\n      role {req.get('role')}, rule '{req.get('rule')}', {left}s left"


@approvals_app.command("list")
def approvals_list(folder: DirOption = None) -> None:
    """List calls waiting for a decision."""
    pending = _queue(folder).pending()
    if not pending:
        console.print("No calls are waiting for approval.")
        return
    for req in pending:
        console.print(_describe(req))


def _decide(request_id: str, approve: bool, folder: Path | None, note: str, by: str | None) -> None:
    try:
        _queue(folder).decide(request_id, approve, by=by, note=note)
    except KeyError:
        err.print(f"[red]No pending request {request_id}[/red] (it may have timed out)")
        raise typer.Exit(1) from None
    console.print(f"{'Approved' if approve else 'Denied'} {request_id}.")


@approvals_app.command("approve")
def approvals_approve(
    request_id: str,
    folder: DirOption = None,
    note: Annotated[str, typer.Option("--note", help="Reason, kept in the audit log.")] = "",
    by: Annotated[str | None, typer.Option("--by", help="Approver name. Default: your login name.")] = None,
) -> None:
    """Let one waiting call through."""
    _decide(request_id, True, folder, note, by)


@approvals_app.command("deny")
def approvals_deny(
    request_id: str,
    folder: DirOption = None,
    note: Annotated[str, typer.Option("--note", help="Reason, shown to the agent and kept in the log.")] = "",
    by: Annotated[str | None, typer.Option("--by", help="Approver name. Default: your login name.")] = None,
) -> None:
    """Refuse one waiting call."""
    _decide(request_id, False, folder, note, by)


@approvals_app.command("watch")
def approvals_watch(
    folder: DirOption = None,
    once: Annotated[bool, typer.Option("--once", help="Answer what is waiting now, then exit.")] = False,
) -> None:
    """Prompt for each call as it arrives. Ctrl+C to stop."""
    queue = _queue(folder)
    who = current_user()
    seen: set[str] = set()
    console.print(f"Watching {queue.folder} for approval requests (Ctrl+C to stop)…")
    try:
        while True:
            for req in queue.pending():
                if req["id"] in seen:
                    continue
                seen.add(req["id"])
                console.print(_describe(req))
                answer = typer.prompt("      Approve? [y/N]", default="n", show_default=False).strip().lower()
                approved = answer in ("y", "yes")
                note = "" if approved else typer.prompt("      Reason (optional)", default="", show_default=False)
                try:
                    queue.decide(req["id"], approved, by=who, note=note)
                    console.print("      [green]approved[/green]" if approved else "      [red]denied[/red]")
                except KeyError:
                    console.print("      [dim]already timed out[/dim]")
            if once:
                return
            time.sleep(0.3)
    except (KeyboardInterrupt, typer.Abort):
        console.print("Stopped.")


def main() -> None:
    app()
