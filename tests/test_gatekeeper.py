"""The proxy's message handling, with in-memory senders instead of pipes."""

from __future__ import annotations

import threading
import time

import pytest

from mcp_gatekeeper.approvals import ApprovalQueue
from mcp_gatekeeper.audit import AuditLog, read_entries, verify
from mcp_gatekeeper.policy import load_policy
from mcp_gatekeeper.proxy import Gatekeeper


class Harness:
    def __init__(self, tmp_path, policy_path, role="finance-agent"):
        self.to_client: list = []
        self.to_server: list = []
        self.log_path = tmp_path / "audit.jsonl"
        self.queue = ApprovalQueue(tmp_path / "approvals", poll_interval=0.01)
        self.gate = Gatekeeper(
            load_policy(policy_path),
            AuditLog(self.log_path),
            self.queue,
            send_client=self.to_client.append,
            send_upstream=self.to_server.append,
            server="payments",
            role=role,
            log=lambda msg: None,
        )

    def call(self, msg_id, tool, args, meta=None):
        params = {"name": tool, "arguments": args}
        if meta:
            params["_meta"] = meta
        self.gate.from_client({"jsonrpc": "2.0", "id": msg_id, "method": "tools/call", "params": params})

    def entries(self):
        return [e for _, e, _ in read_entries(self.log_path)]

    def wait_pending(self):
        for _ in range(200):
            if self.queue.pending():
                return self.queue.pending()[0]
            time.sleep(0.01)
        raise AssertionError("no approval request appeared")


@pytest.fixture
def h(tmp_path, example_policy):
    return Harness(tmp_path, example_policy)


def test_allowed_call_is_forwarded_and_result_logged(h):
    h.call(1, "get_balance", {"account_id": "ACC-001"})
    assert h.to_server[0]["id"] == 1 and h.to_client == []
    h.gate.from_upstream({"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "ok"}]}})
    assert h.to_client[0]["result"]["content"][0]["text"] == "ok"
    call, result = h.entries()
    assert (call["decision"], call["outcome"], call["rule"]) == ("allow", "forwarded", "read-only lookups")
    assert result["event"] == "tool_result" and result["is_error"] is False


def test_denied_call_never_reaches_the_server(h):
    h.call(2, "transfer_funds", {"from_account": "ACC-001", "to_account": "EXT-1", "amount": 5})
    assert h.to_server == []
    reply = h.to_client[0]
    assert reply["id"] == 2 and reply["result"]["isError"] is True
    assert "no payments to external accounts" in reply["result"]["content"][0]["text"]
    assert h.entries()[0]["outcome"] == "blocked"


def test_approved_call_goes_through(h):
    h.call(3, "transfer_funds", {"from_account": "ACC-001", "to_account": "ACC-002", "amount": 5000})
    req = h.wait_pending()
    assert h.to_server == []
    # other traffic keeps flowing while the approval waits
    h.gate.from_client({"jsonrpc": "2.0", "id": 4, "method": "ping"})
    assert h.to_server[0]["method"] == "ping"
    h.queue.decide(req["id"], True, by="alice")
    h.gate.wait_for_approvals()
    assert h.to_server[-1]["id"] == 3
    events = [(e["event"], e.get("outcome"), e.get("approved"), e.get("by")) for e in h.entries()]
    assert events == [("tool_call", "awaiting_approval", None, None), ("approval", None, True, "alice")]


def test_rejected_call_tells_the_agent_who_and_why(h):
    h.call(5, "add_payee", {"name": "X", "iban": "GB82 WEST 1234 5698 7654 32"})
    req = h.wait_pending()
    assert req["arguments"]["iban"] == "[REDACTED:iban …5432]"  # approvers see masked data too
    h.queue.decide(req["id"], False, by="bob", note="unknown payee")
    h.gate.wait_for_approvals()
    assert h.to_server == []
    text = h.to_client[0]["result"]["content"][0]["text"]
    assert "bob rejected" in text and "unknown payee" in text


def test_cancelled_while_waiting_is_never_forwarded(h):
    h.call(6, "add_payee", {"name": "X", "iban": "x"})
    h.wait_pending()
    h.gate.from_client({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 6}})
    h.gate.wait_for_approvals()
    assert h.to_server == [] and h.to_client == []
    assert h.entries()[-1]["by"] == "client"


def test_secrets_are_redacted_in_the_log(h):
    h.call(7, "get_balance", {"account_id": "ACC-001", "token": "abc", "contact": "jane@example.com"})
    entry = h.entries()[0]
    assert entry["arguments"] == {"account_id": "ACC-001", "token": "[REDACTED]", "contact": "[REDACTED:email]"}
    assert entry["redacted"] == ["email", "secret-key"]
    assert h.to_server[0]["params"]["arguments"]["token"] == "abc"  # the server still gets the real call


def test_tools_list_hides_always_denied_tools(h):
    h.gate.from_client({"jsonrpc": "2.0", "id": 8, "method": "tools/list"})
    tools = [{"name": n} for n in ("get_balance", "transfer_funds", "add_payee", "delete_account")]
    h.gate.from_upstream({"jsonrpc": "2.0", "id": 8, "result": {"tools": tools, "cacheScope": "public"}})
    result = h.to_client[0]["result"]
    assert [t["name"] for t in result["tools"]] == ["get_balance", "transfer_funds", "add_payee"]
    assert result["cacheScope"] == "private"


def test_batches_are_rejected(h):
    h.gate.from_client([{"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "delete_account"}}])
    assert h.to_server == []
    assert h.to_client[0][0]["error"]["code"] == -32600


def test_tools_call_without_an_id_is_dropped(h):
    h.gate.from_client(
        {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "delete_account", "arguments": {}}}
    )
    assert h.to_server == [] and h.to_client == []


def test_missing_tool_name_is_an_error(h):
    h.gate.from_client({"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": {}})
    assert h.to_client[0]["error"]["code"] == -32602


def test_modern_requests_get_result_type(h):
    h.call(11, "delete_account", {}, meta={"io.modelcontextprotocol/protocolVersion": "2026-07-28"})
    assert h.to_client[0]["result"]["resultType"] == "complete"


def test_audit_failure_blocks_the_call(tmp_path, example_policy):
    h = Harness(tmp_path, example_policy)
    h.log_path.write_text("{broken\n")  # the proxy can't extend a corrupted log
    h.call(12, "get_balance", {"account_id": "ACC-001"})
    assert h.to_server == []
    assert "audit log could not be written" in h.to_client[0]["result"]["content"][0]["text"]


def test_unrelated_messages_pass_through_untouched(h):
    msgs = [
        {"jsonrpc": "2.0", "id": "a", "method": "initialize", "params": {"protocolVersion": "2025-11-25"}},
        {"jsonrpc": "2.0", "id": "b", "method": "server/discover", "params": {}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 99, "result": {"roots": []}},  # client answering a server request
    ]
    for m in msgs:
        h.gate.from_client(m)
    assert h.to_server == msgs and not h.log_path.exists()


def test_parallel_calls_keep_a_valid_chain(h):
    threads = [threading.Thread(target=h.call, args=(i, "get_balance", {"account_id": "ACC-001"})) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(h.to_server) == 20 and verify(h.log_path).ok
