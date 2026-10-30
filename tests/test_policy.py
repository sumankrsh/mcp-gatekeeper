from __future__ import annotations

import pytest

from mcp_gatekeeper.policy import PolicyError, load_policy, parse_policy

POLICY = """
version: 1
default: deny
rules:
  - name: reads
    tools: [get_*, "payments.list_*"]
    action: allow
  - name: no external
    tools: [transfer_funds]
    when: {to_account: {matches: "EXT-*"}}
    action: deny
  - name: big
    tools: [transfer_funds]
    when: {amount: {gt: 1000}}
    action: approve
  - name: small
    tools: [transfer_funds]
    roles: [finance-agent]
    action: allow
    rate_limit: {calls: 2, per_seconds: 60}
"""


@pytest.fixture
def policy():
    return parse_policy(POLICY)


def test_first_matching_rule_wins(policy):
    # 5000 to an external account matches both "no external" and "big"; the earlier rule decides.
    d = policy.evaluate("transfer_funds", {"to_account": "EXT-9", "amount": 5000}, "finance-agent")
    assert (d.action, d.rule) == ("deny", "no external")


def test_argument_conditions(policy):
    assert (
        policy.evaluate("transfer_funds", {"to_account": "ACC-2", "amount": 5000}, "finance-agent").action == "approve"
    )
    assert policy.evaluate("transfer_funds", {"to_account": "ACC-2", "amount": 50}, "finance-agent").action == "allow"


def test_roles_limit_a_rule(policy):
    d = policy.evaluate("transfer_funds", {"to_account": "ACC-2", "amount": 50}, "support-agent")
    assert (d.action, d.rule) == ("deny", "default")


def test_globs_and_server_qualified_names(policy):
    assert policy.evaluate("get_balance", {}).action == "allow"
    assert policy.evaluate("list_payees", {}, server="payments").action == "allow"
    assert policy.evaluate("list_payees", {}, server="crm").action == "deny"


def test_wrong_type_fails_closed_for_deny_and_approve(policy):
    # An agent sending a string can't dodge the approval threshold.
    d = policy.evaluate("transfer_funds", {"to_account": "ACC-2", "amount": "a lot"}, "finance-agent")
    assert d.action == "approve"
    assert "fail closed" in d.reason
    # Numeric strings are compared as numbers.
    assert (
        policy.evaluate("transfer_funds", {"to_account": "ACC-2", "amount": "5,000"}, "finance-agent").action
        == "approve"
    )


def test_wrong_type_never_satisfies_an_allow_rule():
    p = parse_policy("rules:\n  - {tools: [pay], when: {amount: {lte: 10}}, action: allow}\n")
    assert p.evaluate("pay", {"amount": "free"}).action == "deny"
    assert p.evaluate("pay", {}).action == "deny"


def test_all_operators():
    p = parse_policy(
        """
rules:
  - name: r
    tools: [t]
    action: allow
    when:
      a: {equals: 1}
      b: {in: [x, y]}
      c: {regex: "^ab+c$"}
      d: {contains: "needle"}
      e: {exists: false}
      f.g: {not_equals: 2, not_in: [3], gte: 0, lt: 10}
"""
    )
    good = {"a": 1, "b": "x", "c": "abbbc", "d": "hayneedlehay", "f": {"g": 5}}
    assert p.evaluate("t", good).action == "allow"
    for key, bad in [("a", 2), ("b", "z"), ("c", "ac"), ("d", "hay"), ("e", 1), ("f", {"g": 3})]:
        assert p.evaluate("t", {**good, key: bad}).action == "deny", key


def test_rate_limit_denies_after_limit(policy):
    args = {"to_account": "ACC-2", "amount": 10}
    assert policy.decide("transfer_funds", args, "finance-agent", now=0).action == "allow"
    assert policy.decide("transfer_funds", args, "finance-agent", now=1).action == "allow"
    third = policy.decide("transfer_funds", args, "finance-agent", now=2)
    assert third.action == "deny" and third.rate_limited
    assert policy.decide("transfer_funds", args, "finance-agent", now=61).action == "allow"


def test_tool_visibility(policy):
    assert policy.tool_visible("transfer_funds", "finance-agent")
    assert policy.tool_visible("get_balance")
    assert not policy.tool_visible("delete_account")
    p = parse_policy(
        "default: allow\nrules:\n  - {tools: [rm], action: deny}\n  - {tools: [x], when: {a: 1}, action: deny}\n"
    )
    assert not p.tool_visible("rm")
    assert p.tool_visible("x")  # only some calls are denied


@pytest.mark.parametrize(
    "text, message",
    [
        ("rules:\n  - {tools: [a], action: maybe}", "action must be one of"),
        ("rules:\n  - {action: allow}", "needs 'tools'"),
        ("rules:\n  - {tools: [a], action: allow, when: {x: {bigger: 1}}}", "unknown operator"),
        ("rules:\n  - {tools: [a], action: allow, when: {x: {gt: lots}}}", "needs a number"),
        ("rules:\n  - {tools: [a], action: allow, when: {x: {regex: '('}}}", "not a valid regex"),
        ("rules:\n  - {name: r, tools: [a], action: allow}\n  - {name: r, tools: [b], action: deny}", "unique"),
        ("rules:\n  - {tools: [a], action: allow, rate_limit: {calls: 0, per_seconds: 1}}", "rate_limit"),
        ("defualt: deny", "unknown top-level keys"),
        ("version: 2", "version 1"),
        ("- just a list", "mapping"),
    ],
)
def test_invalid_policies_are_rejected(text, message):
    with pytest.raises(PolicyError, match=message):
        parse_policy(text)


def test_example_policy_loads(example_policy):
    p = load_policy(example_policy)
    assert p.default == "deny" and len(p.rules) == 5
    assert len(p.sha256) == 64


def test_missing_policy_file(tmp_path):
    with pytest.raises(PolicyError, match="cannot read"):
        load_policy(tmp_path / "nope.yaml")
