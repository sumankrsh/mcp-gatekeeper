"""End to end: the real proxy process between a client and a server, over stdio."""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_gatekeeper.audit import read_entries, verify

SDK_SERVER = '''
from mcp.server.mcpserver import MCPServer

app = MCPServer("sdk-payments")


@app.tool()
def transfer_funds(to_account: str, amount: float) -> str:
    """Move money."""
    return f"sent {amount} to {to_account}"


@app.tool()
def wipe_ledger() -> str:
    """Delete everything."""
    return "wiped"


app.run()
'''

POLICY = """
version: 1
default: deny
rules:
  - name: small transfers
    tools: [transfer_funds]
    when: {amount: {lte: 100}}
    action: allow
"""


def _proxy_args(tmp_path: Path, policy: Path, server: list[str]) -> list[str]:
    return [
        "-m",
        "mcp_gatekeeper",
        "run",
        "-p",
        str(policy),
        "-n",
        "payments",
        "--audit-log",
        str(tmp_path / "audit.jsonl"),
        "--approvals-dir",
        str(tmp_path / "approvals"),
        "--",
        *server,
    ]


def test_raw_json_rpc_through_the_proxy(tmp_path, example_policy, payments_server):
    msgs = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "t", "version": "1"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "get_balance", "arguments": {"account_id": "ACC-001"}},
        },
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "delete_account", "arguments": {"account_id": "ACC-001"}},
        },
    ]
    stdin = "".join(json.dumps(m) + "\n" for m in msgs) + "this is not json\n"
    proc = subprocess.run(
        [sys.executable, *_proxy_args(tmp_path, example_policy, payments_server)],
        input=stdin.encode(),
        capture_output=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    replies = {m.get("id"): m for m in map(json.loads, proc.stdout.decode().splitlines())}
    assert replies[1]["result"]["protocolVersion"] == "2025-06-18"
    assert "delete_account" not in [t["name"] for t in replies[2]["result"]["tools"]]
    assert "25,000.00 EUR" in replies[3]["result"]["content"][0]["text"]
    assert replies[4]["result"]["isError"] is True
    assert replies[None]["error"]["code"] == -32700
    assert b"EXECUTED delete_account" not in proc.stderr
    events = [e["event"] for _, e, _ in read_entries(tmp_path / "audit.jsonl")]
    # the second call can be logged before the first result comes back
    assert events[0] == "proxy_start" and events[-1] == "proxy_stop"
    assert sorted(events[1:-1]) == ["tool_call", "tool_call", "tool_result"]
    assert verify(tmp_path / "audit.jsonl").ok


def test_server_that_fails_to_start(tmp_path, example_policy):
    proc = subprocess.run(
        [sys.executable, *_proxy_args(tmp_path, example_policy, ["/no/such/server"])],
        input=b"",
        capture_output=True,
        timeout=30,
    )
    assert proc.returncode == 127 and b"cannot start" in proc.stderr


async def _sdk_session(tmp_path, policy, server):
    from mcp import Client
    from mcp.client.stdio import StdioServerParameters

    params = StdioServerParameters(command=sys.executable, args=_proxy_args(tmp_path, policy, server))
    async with Client(params) as client:
        tools = [t.name for t in (await client.list_tools()).tools]
        ok = await client.call_tool(
            "transfer_funds", {"to_account": "ACC-002", "amount": 50, "from_account": "ACC-001"}
        )
        blocked = await client.call_tool(
            "transfer_funds", {"to_account": "ACC-002", "amount": 5000, "from_account": "ACC-001"}
        )
        return client.protocol_version, tools, ok, blocked


@pytest.mark.parametrize("era", ["2026-07-28 server (official SDK)", "2025-11-25 server (examples/payments_server.py)"])
def test_official_sdk_client_through_the_proxy(tmp_path, payments_server, era):
    """The official MCP Python SDK client, in its default auto mode, works through the proxy with either protocol era."""
    pytest.importorskip("mcp")
    policy = tmp_path / "policy.yaml"
    policy.write_text(POLICY)
    if era.startswith("2026"):
        script = tmp_path / "sdk_server.py"
        script.write_text(SDK_SERVER)
        server, expected_version = [sys.executable, str(script)], "2026-07-28"
    else:
        server, expected_version = payments_server, "2025-11-25"

    version, tools, ok, blocked = asyncio.run(asyncio.wait_for(_sdk_session(tmp_path, policy, server), 60))
    assert version == expected_version
    assert tools == ["transfer_funds"]  # wipe_ledger / the others are always denied, so hidden
    assert ok.is_error is False
    assert blocked.is_error is True and "Blocked by mcp-gatekeeper" in blocked.content[0].text
    assert verify(tmp_path / "audit.jsonl").ok
