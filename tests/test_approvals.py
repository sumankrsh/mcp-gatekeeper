from __future__ import annotations

import threading
import time

import pytest

from mcp_gatekeeper.approvals import ApprovalQueue


def test_approve_round_trip(tmp_path):
    q = ApprovalQueue(tmp_path, poll_interval=0.01)
    rid = q.submit({"tool": "transfer_funds", "arguments": {"amount": 5000}}, timeout=5)
    [pending] = q.pending()
    assert pending["id"] == rid and pending["arguments"] == {"amount": 5000}
    q.decide(rid, True, by="alice", note="invoice checked")
    result = q.wait(rid, timeout=5)
    assert result.approved and result.by == "alice" and result.note == "invoice checked"
    assert list(tmp_path.iterdir()) == []  # files are cleaned up


def test_deny_from_another_thread(tmp_path):
    q = ApprovalQueue(tmp_path, poll_interval=0.01)
    rid = q.submit({"tool": "t"}, timeout=5)
    threading.Timer(0.05, q.decide, args=(rid, False), kwargs={"by": "bob"}).start()
    result = q.wait(rid, timeout=5)
    assert not result.approved and result.by == "bob" and not result.timed_out


def test_no_answer_times_out_as_denied(tmp_path):
    q = ApprovalQueue(tmp_path, poll_interval=0.01)
    rid = q.submit({"tool": "t"}, timeout=0.1)
    start = time.monotonic()
    result = q.wait(rid, timeout=0.1)
    assert not result.approved and result.timed_out
    assert time.monotonic() - start < 2
    with pytest.raises(KeyError):
        q.decide(rid, True)  # too late


def test_cancelled_wait_stops_early(tmp_path):
    q = ApprovalQueue(tmp_path, poll_interval=0.01)
    rid = q.submit({"tool": "t"}, timeout=30)
    result = q.wait(rid, timeout=30, cancelled=lambda: True)
    assert not result.approved and not result.timed_out


def test_expired_and_answered_requests_are_not_pending(tmp_path):
    q = ApprovalQueue(tmp_path)
    old = q.submit({"tool": "a"}, timeout=-1)
    answered = q.submit({"tool": "b"}, timeout=30)
    q.decide(answered, True)
    assert old and q.pending() == []
