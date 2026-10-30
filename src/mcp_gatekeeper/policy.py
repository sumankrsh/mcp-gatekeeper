"""Load a YAML policy and decide what happens to a tool call.

Rules are checked in order and the first one that matches wins, like a
firewall. A rule matches when the tool name fits one of its patterns, the
gatekeeper's role is in its `roles` list (if it has one) and every condition
in `when` holds for the call's arguments.
"""

from __future__ import annotations

import fnmatch
import hashlib
import re
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ACTIONS = ("allow", "deny", "approve")
OPERATORS = ("equals", "not_equals", "in", "not_in", "matches", "regex", "contains", "gt", "gte", "lt", "lte", "exists")
NUMERIC_OPERATORS = ("gt", "gte", "lt", "lte")


class PolicyError(ValueError):
    """The policy file is missing, unreadable or invalid."""


@dataclass
class RateLimit:
    calls: int
    per_seconds: float


@dataclass
class Rule:
    name: str
    tools: list[str]
    action: str
    roles: list[str] | None = None
    when: dict[str, dict[str, Any]] = field(default_factory=dict)
    rate_limit: RateLimit | None = None

    def matches_tool(self, tool: str, server: str | None) -> bool:
        qualified = f"{server}.{tool}" if server else None
        return any(
            fnmatch.fnmatchcase(tool, p) or (qualified is not None and fnmatch.fnmatchcase(qualified, p))
            for p in self.tools
        )

    def applies_to_role(self, role: str) -> bool:
        return self.roles is None or role in self.roles


@dataclass
class Decision:
    action: str  # allow | deny | approve
    rule: str  # rule name, or "default"
    reason: str
    rate_limited: bool = False


@dataclass
class Policy:
    rules: list[Rule]
    default: str = "deny"
    approval_timeout: float = 120.0
    redact_keys: list[str] = field(default_factory=list)
    redact_patterns: list[str] = field(default_factory=list)
    sha256: str = ""

    def __post_init__(self) -> None:
        self._windows: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    # -- evaluation -------------------------------------------------------

    def evaluate(
        self, tool: str, arguments: dict[str, Any] | None, role: str = "default", server: str | None = None
    ) -> Decision:
        """Decide what to do with one call, without recording it against any rate limit."""
        args = arguments if isinstance(arguments, dict) else {}
        for rule in self.rules:
            if not rule.matches_tool(tool, server) or not rule.applies_to_role(role):
                continue
            matched, notes = _conditions_hold(rule, args)
            if not matched:
                continue
            reason = f"matched rule '{rule.name}'"
            if notes:
                reason += "; " + "; ".join(notes)
            return Decision(rule.action, rule.name, reason)
        return Decision(self.default, "default", f"no rule matched, so the default ({self.default}) applies")

    def decide(
        self,
        tool: str,
        arguments: dict[str, Any] | None,
        role: str = "default",
        server: str | None = None,
        now: float | None = None,
    ) -> Decision:
        """Evaluate a call and count it against its rule's rate limit if it would go through."""
        decision = self.evaluate(tool, arguments, role, server)
        rule = next((r for r in self.rules if r.name == decision.rule), None)
        if decision.action == "deny" or rule is None or rule.rate_limit is None:
            return decision
        limit = rule.rate_limit
        now = time.monotonic() if now is None else now
        with self._lock:
            window = self._windows.setdefault(rule.name, deque())
            while window and now - window[0] >= limit.per_seconds:
                window.popleft()
            if len(window) >= limit.calls:
                return Decision(
                    "deny",
                    rule.name,
                    f"rate limit for rule '{rule.name}' reached ({limit.calls} calls per {limit.per_seconds:g}s)",
                    rate_limited=True,
                )
            window.append(now)
        return decision

    def tool_visible(self, tool: str, role: str = "default", server: str | None = None) -> bool:
        """False when every possible call to this tool would be denied, so it can be hidden from tools/list."""
        for rule in self.rules:
            if not rule.matches_tool(tool, server) or not rule.applies_to_role(role):
                continue
            if rule.action != "deny":
                return True
            if not rule.when:
                return False
        return self.default != "deny"


# -- conditions -----------------------------------------------------------

_MISSING = object()


def _lookup(args: dict[str, Any], path: str) -> Any:
    value: Any = args
    for part in path.split("."):
        if isinstance(value, dict) and part in value:
            value = value[part]
        else:
            return _MISSING
    return value


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip().replace(",", ""))
        except ValueError:
            return None
    return None


def _check(op: str, expected: Any, value: Any) -> bool | None:
    """True or False, or None when the value can't be compared (wrong type)."""
    if op == "exists":
        return (value is not _MISSING) == bool(expected)
    if value is _MISSING:
        return False
    if op == "equals":
        return value == expected
    if op == "not_equals":
        return value != expected
    if op == "in":
        return value in expected
    if op == "not_in":
        return value not in expected
    if op == "matches":
        return fnmatch.fnmatchcase(value, str(expected)) if isinstance(value, str) else None
    if op == "regex":
        return re.search(expected, value) is not None if isinstance(value, str) else None
    if op == "contains":
        if isinstance(value, str | list | tuple):
            return expected in value
        return None
    number = _number(value)
    if number is None:
        return None
    limit = float(expected)
    return {"gt": number > limit, "gte": number >= limit, "lt": number < limit, "lte": number <= limit}[op]


def _conditions_hold(rule: Rule, args: dict[str, Any]) -> tuple[bool, list[str]]:
    """Check every condition of a rule.

    A condition that can't be evaluated (for example `amount: {gt: 1000}` when
    the agent sends `amount: "lots"`) fails closed: it counts as a match for
    deny and approve rules and as no match for allow rules. Otherwise an agent
    could slip past a limit by sending the wrong type.
    """
    notes: list[str] = []
    for path, matchers in rule.when.items():
        value = _lookup(args, path)
        for op, expected in matchers.items():
            result = _check(op, expected, value)
            if result is None:
                if rule.action == "allow":
                    return False, []
                notes.append(
                    f"could not evaluate {path} {op} {expected!r} on {value!r}, so the rule applies (fail closed)"
                )
            elif not result:
                return False, []
    return True, notes


# -- loading --------------------------------------------------------------


def _as_list(value: Any, where: str) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and value and all(isinstance(v, str) for v in value):
        return list(value)
    raise PolicyError(f"{where} must be a string or a non-empty list of strings")


def _parse_rule(raw: Any, index: int) -> Rule:
    where = f"rules[{index}]"
    if not isinstance(raw, dict):
        raise PolicyError(f"{where} must be a mapping")
    unknown = set(raw) - {"name", "tools", "tool", "action", "roles", "when", "rate_limit"}
    if unknown:
        raise PolicyError(f"{where} has unknown keys: {', '.join(sorted(unknown))}")
    if "tools" not in raw and "tool" not in raw:
        raise PolicyError(f"{where} needs 'tools'")
    tools = _as_list(raw.get("tools", raw.get("tool")), f"{where}.tools")
    action = raw.get("action")
    if action not in ACTIONS:
        raise PolicyError(f"{where}.action must be one of {', '.join(ACTIONS)} (got {action!r})")
    name = str(raw.get("name") or f"rule {index + 1}")
    roles = _as_list(raw["roles"], f"{where}.roles") if "roles" in raw else None

    when: dict[str, dict[str, Any]] = {}
    for path, cond in (raw.get("when") or {}).items():
        if not isinstance(cond, dict):
            cond = {"equals": cond}
        for op, expected in cond.items():
            if op not in OPERATORS:
                raise PolicyError(f"{where}.when.{path}: unknown operator '{op}' (use {', '.join(OPERATORS)})")
            if op in NUMERIC_OPERATORS and _number(expected) is None:
                raise PolicyError(f"{where}.when.{path}.{op} needs a number")
            if op in ("in", "not_in") and not isinstance(expected, list):
                raise PolicyError(f"{where}.when.{path}.{op} needs a list")
            if op == "regex":
                try:
                    re.compile(expected)
                except (re.error, TypeError) as exc:
                    raise PolicyError(f"{where}.when.{path}.regex is not a valid regex: {exc}") from exc
        when[str(path)] = dict(cond)

    rate_limit = None
    if "rate_limit" in raw:
        rl = raw["rate_limit"]
        if not isinstance(rl, dict) or not isinstance(rl.get("calls"), int) or rl["calls"] < 1:
            raise PolicyError(f"{where}.rate_limit needs 'calls' (a positive whole number) and 'per_seconds'")
        per = _number(rl.get("per_seconds"))
        if per is None or per <= 0:
            raise PolicyError(f"{where}.rate_limit.per_seconds must be a positive number")
        rate_limit = RateLimit(rl["calls"], per)
    return Rule(name=name, tools=tools, action=action, roles=roles, when=when, rate_limit=rate_limit)


def parse_policy(text: str) -> Policy:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError("the policy must be a YAML mapping")
    unknown = set(data) - {"version", "default", "approval_timeout", "rules", "redact"}
    if unknown:
        raise PolicyError(f"unknown top-level keys: {', '.join(sorted(unknown))}")
    if data.get("version", 1) != 1:
        raise PolicyError("only policy version 1 is supported")
    default = data.get("default", "deny")
    if default not in ACTIONS:
        raise PolicyError(f"default must be one of {', '.join(ACTIONS)}")
    timeout = _number(data.get("approval_timeout", 120))
    if timeout is None or timeout <= 0:
        raise PolicyError("approval_timeout must be a positive number of seconds")
    raw_rules = data.get("rules") or []
    if not isinstance(raw_rules, list):
        raise PolicyError("rules must be a list")
    rules = [_parse_rule(r, i) for i, r in enumerate(raw_rules)]
    names = [r.name for r in rules]
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        raise PolicyError(f"rule names must be unique: {', '.join(dupes)}")

    redact = data.get("redact") or {}
    if not isinstance(redact, dict) or set(redact) - {"keys", "patterns"}:
        raise PolicyError("redact may only contain 'keys' and 'patterns'")
    keys = [str(k) for k in redact.get("keys") or []]
    patterns = [str(p) for p in redact.get("patterns") or []]
    for p in patterns:
        try:
            re.compile(p)
        except re.error as exc:
            raise PolicyError(f"redact pattern {p!r} is not a valid regex: {exc}") from exc
    return Policy(
        rules=rules,
        default=default,
        approval_timeout=timeout,
        redact_keys=keys,
        redact_patterns=patterns,
        sha256=hashlib.sha256(text.encode()).hexdigest(),
    )


def load_policy(path: str | Path) -> Policy:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"cannot read {p}: {exc.strerror or exc}") from exc
    try:
        return parse_policy(text)
    except PolicyError as exc:
        raise PolicyError(f"{p}: {exc}") from exc
