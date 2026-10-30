"""A fake payments MCP server for trying mcp-gatekeeper. Synthetic data, no real money.

It speaks MCP over stdio (newline-delimited JSON-RPC) using the initialize
handshake, protocol revisions 2024-11-05 to 2025-11-25, and only needs the
Python standard library. Clients that try the newer `server/discover` probe
get "method not found" and fall back to initialize, as the spec intends.

    python examples/payments_server.py

Every executed transfer is also written to stderr, so you can see what
actually ran as well as what the agent attempted.
"""

from __future__ import annotations

import json
import sys

SUPPORTED_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")

ACCOUNTS = {
    "ACC-001": {"owner": "Northwind Operations (synthetic)", "balance": 25_000.00, "currency": "EUR"},
    "ACC-002": {"owner": "Contoso Supplies (synthetic)", "balance": 4_200.00, "currency": "EUR"},
}
PAYEES: list[dict] = []

TOOLS = [
    {
        "name": "get_balance",
        "description": "Get the balance of an account.",
        "inputSchema": {
            "type": "object",
            "properties": {"account_id": {"type": "string"}},
            "required": ["account_id"],
        },
    },
    {
        "name": "transfer_funds",
        "description": "Move money from one account to another account or payee.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "from_account": {"type": "string"},
                "to_account": {"type": "string"},
                "amount": {"type": "number"},
                "currency": {"type": "string"},
                "reference": {"type": "string"},
            },
            "required": ["from_account", "to_account", "amount"],
        },
    },
    {
        "name": "add_payee",
        "description": "Save a new payee with their bank details.",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string"}, "iban": {"type": "string"}, "email": {"type": "string"}},
            "required": ["name", "iban"],
        },
    },
    {
        "name": "delete_account",
        "description": "Close an account permanently.",
        "inputSchema": {
            "type": "object",
            "properties": {"account_id": {"type": "string"}},
            "required": ["account_id"],
        },
    },
]


def text(value: str, error: bool = False) -> dict:
    result = {"content": [{"type": "text", "text": value}]}
    if error:
        result["isError"] = True
    return result


def call_tool(name: str, args: dict) -> dict:
    if name == "get_balance":
        acc = ACCOUNTS.get(args.get("account_id", ""))
        if acc is None:
            return text(f"Unknown account {args.get('account_id')!r}", error=True)
        return text(f"{args['account_id']}: {acc['balance']:,.2f} {acc['currency']}")
    if name == "transfer_funds":
        src = ACCOUNTS.get(args.get("from_account", ""))
        try:
            amount = float(args.get("amount"))
        except (TypeError, ValueError):
            return text("amount must be a number", error=True)
        if src is None:
            return text(f"Unknown account {args.get('from_account')!r}", error=True)
        if amount <= 0 or amount > src["balance"]:
            return text("Insufficient funds or invalid amount", error=True)
        src["balance"] -= amount
        if args.get("to_account") in ACCOUNTS:
            ACCOUNTS[args["to_account"]]["balance"] += amount
        line = f"transferred {amount:,.2f} {args.get('currency', 'EUR')} from {args['from_account']} to {args.get('to_account')}"
        print(f"payments-server: EXECUTED {line}", file=sys.stderr, flush=True)
        return text(f"Done: {line}")
    if name == "add_payee":
        PAYEES.append(dict(args))
        return text(f"Saved payee {args.get('name')!r} ({len(PAYEES)} payees)")
    if name == "delete_account":
        if ACCOUNTS.pop(args.get("account_id", ""), None) is None:
            return text("Unknown account", error=True)
        print(f"payments-server: EXECUTED delete_account {args['account_id']}", file=sys.stderr, flush=True)
        return text(f"Deleted {args['account_id']}")
    raise KeyError(name)


def handle(msg: dict) -> dict | None:
    method, msg_id, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
    if method is None or msg_id is None:
        return None  # a notification or a response; nothing to answer
    if method == "initialize":
        asked = params.get("protocolVersion")
        result = {
            "protocolVersion": asked if asked in SUPPORTED_VERSIONS else SUPPORTED_VERSIONS[-1],
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "fake-payments", "version": "1.0.0"},
        }
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        try:
            result = call_tool(params.get("name", ""), params.get("arguments") or {})
        except KeyError:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32602, "message": f"Unknown tool {params.get('name')!r}"},
            }
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}


def main() -> None:
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
        else:
            reply = handle(msg) if isinstance(msg, dict) else None
        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
