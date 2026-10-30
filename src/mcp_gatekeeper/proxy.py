"""The proxy: sits between an MCP client and one MCP server over stdio.

Only two kinds of message are touched:

- `tools/call` requests are checked against the policy. Allowed calls are
  forwarded, denied calls are answered by the proxy with an error result, and
  calls that need approval wait for a person.
- `tools/list` responses have tools removed that the policy would always deny,
  so the agent doesn't plan around them.

Everything else (initialize or server/discover, resources, prompts,
notifications, server-to-client requests) is passed through unchanged, which
keeps the proxy independent of the protocol revision the two sides agree on.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from typing import IO, Any

from .approvals import ApprovalQueue
from .audit import AuditLog
from .policy import Policy
from .redact import Redactor

Message = Any
Sender = Callable[[Message], None]

PROTOCOL_VERSION_META_KEY = "io.modelcontextprotocol/protocolVersion"
INVALID_REQUEST = -32600
INVALID_PARAMS = -32602
PARSE_ERROR = -32700


def _key(request_id: Any) -> str:
    # 1 and "1" are different JSON-RPC ids.
    return json.dumps(request_id, sort_keys=True)


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def blocked_result(request: dict[str, Any], text: str) -> dict[str, Any]:
    """A tool result with isError set, so the model sees why the call didn't run."""
    result: dict[str, Any] = {"content": [{"type": "text", "text": text}], "isError": True}
    meta = (request.get("params") or {}).get("_meta") or {}
    if isinstance(meta, dict) and PROTOCOL_VERSION_META_KEY in meta:
        result["resultType"] = "complete"  # required on 2026-07-28 and later
    return {"jsonrpc": "2.0", "id": request.get("id"), "result": result}


class Gatekeeper:
    """Message-level policy enforcement, independent of how messages are transported."""

    def __init__(
        self,
        policy: Policy,
        audit: AuditLog,
        approvals: ApprovalQueue,
        *,
        send_client: Sender,
        send_upstream: Sender,
        server: str = "server",
        role: str = "default",
        hide_denied_tools: bool = True,
        log: Callable[[str], None] | None = None,
    ) -> None:
        self.policy = policy
        self.audit = audit
        self.approvals = approvals
        self.send_client = send_client
        self.send_upstream = send_upstream
        self.server = server
        self.role = role
        self.hide_denied_tools = hide_denied_tools
        self.redactor = Redactor(policy.redact_keys, policy.redact_patterns)
        self.log = log or (lambda msg: print(f"mcp-gatekeeper: {msg}", file=sys.stderr, flush=True))
        self._lock = threading.Lock()
        self._inflight: dict[str, tuple[str, float]] = {}
        self._list_requests: set[str] = set()
        self._cancelled: set[str] = set()
        self._waiting: set[str] = set()
        self._threads: list[threading.Thread] = []

    # -- client -> server ---------------------------------------------------

    def from_client(self, msg: Message) -> None:
        if isinstance(msg, list):
            # Batches were removed from MCP in 2025-06-18. Rejecting them keeps a
            # tools/call from slipping past the policy inside an array.
            errors = [
                _error(m.get("id"), INVALID_REQUEST, "JSON-RPC batches are not supported by mcp-gatekeeper")
                for m in msg
                if isinstance(m, dict) and "id" in m and "method" in m
            ]
            if errors:
                self.send_client(errors)
            return
        if not isinstance(msg, dict):
            self.send_client(_error(None, INVALID_REQUEST, "expected a JSON-RPC object"))
            return
        method = msg.get("method")
        if method == "tools/call":
            if "id" in msg:
                self._gate(msg)
            else:
                # A tools/call without an id is a notification: nothing to answer, and never forwarded.
                self.log("dropped a tools/call sent as a notification (no id)")
            return
        if method == "tools/list" and "id" in msg:
            with self._lock:
                self._list_requests.add(_key(msg["id"]))
        if method == "notifications/cancelled":
            target = _key((msg.get("params") or {}).get("requestId"))
            with self._lock:
                if target in self._waiting:
                    self._cancelled.add(target)
                    return  # the server never saw this request
        self.send_upstream(msg)

    def _gate(self, msg: dict[str, Any]) -> None:
        request_id = msg["id"]
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        tool = params.get("name")
        if not isinstance(tool, str) or not tool:
            self.send_client(_error(request_id, INVALID_PARAMS, "tools/call needs a tool name"))
            return
        arguments = params.get("arguments")
        decision = self.policy.decide(tool, arguments if isinstance(arguments, dict) else None, self.role, self.server)
        shown_args, redactions = self.redactor.redact(arguments if arguments is not None else {})
        record = {
            "server": self.server,
            "role": self.role,
            "call_id": request_id,
            "tool": tool,
            "arguments": shown_args,
            "redacted": redactions,
            "decision": decision.action,
            "rule": decision.rule,
            "reason": decision.reason,
        }
        if decision.action == "deny":
            if self._record("tool_call", **record, outcome="blocked"):
                self.send_client(blocked_result(msg, f"Blocked by mcp-gatekeeper policy: {decision.reason}."))
            return
        if decision.action == "allow":
            if self._record("tool_call", **record, outcome="forwarded"):
                self._forward_call(msg, tool)
            return
        # approve: wait on a person without holding up other traffic
        request_key = _key(request_id)
        with self._lock:
            self._waiting.add(request_key)
        thread = threading.Thread(target=self._await_approval, args=(msg, tool, record, request_key), daemon=True)
        with self._lock:
            self._threads.append(thread)
        thread.start()

    def _await_approval(self, msg: dict[str, Any], tool: str, record: dict[str, Any], request_key: str) -> None:
        try:
            timeout = self.policy.approval_timeout
            details = {k: record[k] for k in ("server", "role", "tool", "arguments", "rule", "reason")}
            try:
                approval_id = self.approvals.submit(details, timeout)
            except OSError as exc:
                self.log(f"cannot write to the approvals folder ({exc}); refusing the call")
                if self._record("tool_call", **record, outcome="blocked", note="approvals folder not writable"):
                    self.send_client(
                        blocked_result(
                            msg, "Blocked by mcp-gatekeeper: approval was needed but could not be requested."
                        )
                    )
                return
            if not self._record("tool_call", **record, outcome="awaiting_approval", approval_id=approval_id):
                return
            self.log(f"approval needed for {tool} (id {approval_id}); answer with: mcp-gatekeeper approvals watch")
            result = self.approvals.wait(approval_id, timeout, cancelled=lambda: request_key in self._cancelled)
            if request_key in self._cancelled:
                self._record(
                    "approval",
                    call_id=msg["id"],
                    tool=tool,
                    approval_id=approval_id,
                    approved=False,
                    by="client",
                    note="request cancelled by the client",
                )
                return
            if not self._record(
                "approval",
                call_id=msg["id"],
                tool=tool,
                approval_id=approval_id,
                approved=result.approved,
                by=result.by,
                note=result.note,
                timed_out=result.timed_out,
            ):
                return
            if result.approved:
                self._forward_call(msg, tool)
            elif result.timed_out:
                self.send_client(
                    blocked_result(msg, f"Blocked by mcp-gatekeeper: no approval within {timeout:g}s for {tool}.")
                )
            else:
                note = f" Note from the approver: {result.note}" if result.note else ""
                self.send_client(
                    blocked_result(msg, f"Blocked by mcp-gatekeeper: {result.by} rejected this {tool} call.{note}")
                )
        finally:
            with self._lock:
                self._waiting.discard(request_key)
                self._cancelled.discard(request_key)

    def _forward_call(self, msg: dict[str, Any], tool: str) -> None:
        with self._lock:
            self._inflight[_key(msg["id"])] = (tool, time.monotonic())
        self.send_upstream(msg)

    def _record(self, event: str, **fields: Any) -> bool:
        """Write an audit entry. If that fails, the call is refused: no log, no call."""
        try:
            self.audit.append(event, **fields)
            return True
        except Exception as exc:  # disk full, permissions, a corrupted log
            self.log(f"audit log write failed ({exc}); refusing the call")
            if event == "tool_call" and "call_id" in fields:
                request = {"id": fields["call_id"], "params": {}}
                self.send_client(
                    blocked_result(request, "Blocked by mcp-gatekeeper: the audit log could not be written.")
                )
            return False

    # -- server -> client ---------------------------------------------------

    def from_upstream(self, msg: Message) -> None:
        if isinstance(msg, dict) and "method" not in msg and "id" in msg:
            key = _key(msg["id"])
            with self._lock:
                is_list = key in self._list_requests
                self._list_requests.discard(key)
                call = self._inflight.pop(key, None)
            if is_list and self.hide_denied_tools:
                self._filter_tools(msg)
            if call is not None:
                tool, started = call
                result = msg.get("result") if isinstance(msg.get("result"), dict) else {}
                self._record(
                    "tool_result",
                    server=self.server,
                    call_id=msg["id"],
                    tool=tool,
                    is_error=bool("error" in msg or result.get("isError")),
                    duration_ms=round((time.monotonic() - started) * 1000, 1),
                )
        self.send_client(msg)

    def _filter_tools(self, msg: dict[str, Any]) -> None:
        result = msg.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            return
        kept = [
            t
            for t in result["tools"]
            if not isinstance(t, dict) or self.policy.tool_visible(str(t.get("name", "")), self.role, self.server)
        ]
        if len(kept) != len(result["tools"]):
            result["tools"] = kept
            if result.get("cacheScope") == "public":
                result["cacheScope"] = "private"  # the filtered list depends on this proxy's role

    def wait_for_approvals(self, timeout: float = 10.0) -> None:
        """Block until approval threads finish (used by tests and on shutdown)."""
        deadline = time.monotonic() + timeout
        for thread in list(self._threads):
            thread.join(max(0.0, deadline - time.monotonic()))


class _LineWriter:
    """Writes one JSON message per line, as MCP's stdio transport requires."""

    def __init__(self, stream: IO[bytes]) -> None:
        self.stream = stream
        self.lock = threading.Lock()

    def __call__(self, msg: Message) -> None:
        data = json.dumps(msg, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
        with self.lock:
            try:
                self.stream.write(data)
                self.stream.flush()
            except (BrokenPipeError, ValueError, OSError):
                pass


def run_stdio(
    command: list[str],
    policy: Policy,
    audit: AuditLog,
    approvals: ApprovalQueue,
    *,
    server: str,
    role: str,
    hide_denied_tools: bool = True,
    client_in: IO[bytes] | None = None,
    client_out: IO[bytes] | None = None,
) -> int:
    """Start the upstream server and relay messages until either side closes. Returns the server's exit code."""
    client_in = client_in or sys.stdin.buffer
    client_out = client_out or sys.stdout.buffer
    try:
        upstream = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None)
    except OSError as exc:
        print(f"mcp-gatekeeper: cannot start {command[0]}: {exc}", file=sys.stderr)
        return 127
    assert upstream.stdin is not None and upstream.stdout is not None

    to_client = _LineWriter(client_out)
    to_upstream = _LineWriter(upstream.stdin)
    gate = Gatekeeper(
        policy,
        audit,
        approvals,
        send_client=to_client,
        send_upstream=to_upstream,
        server=server,
        role=role,
        hide_denied_tools=hide_denied_tools,
    )
    audit.append("proxy_start", server=server, role=role, command=command, policy_sha256=policy.sha256)

    def pump_upstream() -> None:
        for line in upstream.stdout:  # type: ignore[union-attr]
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                with to_client.lock:  # not JSON-RPC; pass it on untouched
                    client_out.write(line if line.endswith(b"\n") else line + b"\n")
                    client_out.flush()
                continue
            gate.from_upstream(msg)

    client_closed = threading.Event()

    def pump_client() -> None:
        for line in client_in:
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                to_client(_error(None, PARSE_ERROR, "invalid JSON"))
                continue
            gate.from_client(msg)
        client_closed.set()

    reader = threading.Thread(target=pump_upstream, daemon=True)
    reader.start()
    threading.Thread(target=pump_client, daemon=True).start()
    # Stop when the client hangs up or the server exits, whichever comes first.
    while not client_closed.wait(0.1) and upstream.poll() is None:
        pass

    try:
        upstream.stdin.close()
    except OSError:
        pass
    try:
        code = upstream.wait(timeout=5)
    except subprocess.TimeoutExpired:
        upstream.terminate()
        code = upstream.wait(timeout=5)
    reader.join(timeout=2)
    audit.append("proxy_stop", server=server, exit_code=code)
    return code
