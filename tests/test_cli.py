from __future__ import annotations

import json

from typer.testing import CliRunner

from mcp_gatekeeper.approvals import ApprovalQueue
from mcp_gatekeeper.audit import AuditLog
from mcp_gatekeeper.cli import app

runner = CliRunner()


def test_validate_lists_rules(example_policy):
    result = runner.invoke(app, ["validate", str(example_policy)])
    assert result.exit_code == 0, result.output
    assert "valid (5 rules, approval timeout 120s)" in result.output


def test_validate_reports_errors(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("rules:\n  - {tools: [a], action: perhaps}\n")
    result = runner.invoke(app, ["validate", str(bad)])
    assert result.exit_code == 2 and "action must be one of" in result.output


def test_explain_exit_codes(example_policy):
    base = ["explain", str(example_policy), "transfer_funds", "-r", "finance-agent", "-a"]
    assert runner.invoke(app, [*base, '{"to_account": "ACC-2", "amount": 10}']).exit_code == 0
    assert runner.invoke(app, [*base, '{"to_account": "EXT-2", "amount": 10}']).exit_code == 1
    approve = runner.invoke(app, [*base, '{"to_account": "ACC-2", "amount": 5000}'])
    assert approve.exit_code == 3 and "APPROVE" in approve.output
    assert runner.invoke(app, [*base, "not json"]).exit_code == 2


def test_audit_verify_and_show(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("tool_call", tool="t", decision="allow", outcome="forwarded", rule="r", arguments={"a": 1})
    log.append("approval", tool="t", approved=True, by="alice")
    ok = runner.invoke(app, ["audit", "verify", str(path)])
    assert ok.exit_code == 0 and "chain intact" in ok.output
    shown = runner.invoke(app, ["audit", "show", str(path)])
    assert "approved by alice" in shown.output
    head = runner.invoke(app, ["audit", "head", str(path)]).output.strip()
    path.write_text(path.read_text().replace("alice", "mallory"))
    bad = runner.invoke(app, ["audit", "verify", str(path), "--expect-head", head])
    assert bad.exit_code == 1 and "line 2" in bad.output


def test_audit_verify_missing_file(tmp_path):
    assert runner.invoke(app, ["audit", "verify", str(tmp_path / "none.jsonl")]).exit_code == 2


def test_approvals_list_approve_deny(tmp_path):
    q = ApprovalQueue(tmp_path)
    a = q.submit(
        {"server": "payments", "tool": "transfer_funds", "arguments": {"amount": 5000}, "role": "r", "rule": "big"}, 60
    )
    b = q.submit({"server": "payments", "tool": "add_payee", "arguments": {}, "role": "r", "rule": "payees"}, 60)
    listed = runner.invoke(app, ["approvals", "list", "-d", str(tmp_path)])
    assert a in listed.output and b in listed.output and "5000" in listed.output
    assert runner.invoke(app, ["approvals", "approve", a, "-d", str(tmp_path), "--by", "alice"]).exit_code == 0
    assert runner.invoke(app, ["approvals", "deny", b, "-d", str(tmp_path), "--note", "no"]).exit_code == 0
    assert q.wait(a, 1).approved and not q.wait(b, 1).approved
    assert runner.invoke(app, ["approvals", "approve", "ffffffff", "-d", str(tmp_path)]).exit_code == 1


def test_approvals_watch_once_prompts(tmp_path):
    q = ApprovalQueue(tmp_path)
    rid = q.submit({"server": "s", "tool": "t", "arguments": {}, "role": "r", "rule": "x"}, 60)
    result = runner.invoke(app, ["approvals", "watch", "-d", str(tmp_path), "--once"], input="y\n")
    assert result.exit_code == 0 and "approved" in result.output
    assert json.loads((tmp_path / f"{rid}.decision.json").read_text())["decision"] == "approve"


def test_demo_runs_end_to_end(tmp_path, monkeypatch, example_policy):
    from pathlib import Path

    server = Path(example_policy).parent / "payments_server.py"
    out = tmp_path / "demo"
    result = runner.invoke(
        app, ["demo", "--approve", "no", "--policy", str(example_policy), "--server", str(server), "--out", str(out)]
    )
    assert result.exit_code == 0, result.output
    assert "transferred 250.00 EUR" in result.output
    assert "2,500.00" not in result.output.split("What actually ran")[1].split("Audit log")[0]  # rejected, never ran
    flat = " ".join(result.output.split())  # long temp paths wrap in the narrow test terminal
    assert ": intact, " in flat and "(the entry was edited)" in flat


def test_demo_without_examples_explains(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["demo", "--approve", "yes"])
    assert result.exit_code == 2 and "project folder" in result.output
