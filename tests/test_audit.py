from __future__ import annotations

import json
import threading

import pytest

from mcp_gatekeeper.audit import AuditLog, verify


def _write(path, n=3, key=None):
    log = AuditLog(path, key)
    for i in range(n):
        log.append("tool_call", tool=f"t{i}", arguments={"amount": 100 * i})
    return log


def _lines(path):
    return path.read_text().splitlines()


def test_intact_chain_verifies(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, 5)
    result = verify(path)
    assert result.ok and result.entries == 5
    entries = [json.loads(line) for line in _lines(path)]
    assert entries[0]["prev"] == "0" * 64
    assert all(b["prev"] == a["hash"] for a, b in zip(entries, entries[1:], strict=False))


def test_edited_entry_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path)
    lines = _lines(path)
    lines[1] = lines[1].replace('"amount":100', '"amount":1')
    path.write_text("\n".join(lines) + "\n")
    result = verify(path)
    assert not result.ok and result.line == 2 and "edited" in result.problem


def test_removed_or_reordered_entries_are_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, 4)
    lines = _lines(path)
    path.write_text("\n".join([lines[0], lines[2], lines[3]]) + "\n")
    assert "removed" in verify(path).problem
    path.write_text("\n".join([lines[0], lines[2], lines[1], lines[3]]) + "\n")
    assert not verify(path).ok


def test_rebuilt_chain_passes_without_a_key_but_not_with_one(tmp_path):
    # A plain hash chain can be recomputed by whoever edits it; HMAC stops that.
    path = tmp_path / "audit.jsonl"
    _write(path, 2, key=b"k1")
    assert not verify(path).ok  # needs the key
    assert "set MCP_GATEKEEPER_AUDIT_KEY" in verify(path).problem
    assert verify(path, key=b"k1").ok
    assert not verify(path, key=b"wrong").ok


def test_downgrade_to_plain_hashes_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, 2)  # unsigned
    result = verify(path, key=b"k1")
    assert not result.ok and "not HMAC-signed" in result.problem


def test_truncation_is_caught_with_an_expected_head(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, 3)
    head = verify(path).head
    assert verify(path, expect_head=head).ok
    path.write_text("\n".join(_lines(path)[:2]) + "\n")
    assert verify(path).ok  # a chain alone can't see a cut-off tail
    result = verify(path, expect_head=head)
    assert not result.ok and "removed from the end" in result.problem


def test_concurrent_appends_keep_the_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    logs = [AuditLog(path) for _ in range(4)]  # separate handles, like separate proxies

    def worker(log):
        for i in range(25):
            log.append("tool_call", tool="t", i=i)

    threads = [threading.Thread(target=worker, args=(log,)) for log in logs]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    result = verify(path)
    assert result.ok and result.entries == 100


def test_garbage_line_is_reported(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write(path, 2)
    with open(path, "a") as fh:
        fh.write("not json\n")
    result = verify(path)
    assert not result.ok and result.line == 3


@pytest.mark.parametrize("n", [1, 300])
def test_last_entry_lookup_handles_small_and_large_logs(tmp_path, n):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(n):
        log.append("x", pad="y" * 50, i=i)
    assert json.loads(_lines(path)[-1])["seq"] == n
    assert verify(path).ok
