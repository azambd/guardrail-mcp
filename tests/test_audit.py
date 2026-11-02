import json
import threading
from pathlib import Path

from guardrail_mcp.audit import GENESIS, AuditLog


def _write(path: Path, n: int) -> AuditLog:
    log = AuditLog(path)
    for i in range(n):
        log.append({"tool": "get_repo", "decision": "allow", "i": i})
    return log


def test_chain_links_and_verifies(tmp_path: Path) -> None:
    log = _write(tmp_path / "audit.jsonl", 3)
    records = log.records()
    assert [r["seq"] for r in records] == [1, 2, 3]
    assert records[0]["prev"] == GENESIS
    assert records[1]["prev"] == records[0]["hash"]
    result = log.verify()
    assert result.ok and result.records == 3


def test_edit_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = _write(path, 4)
    lines = path.read_text().splitlines()
    record = json.loads(lines[1])
    record["decision"] = "deny"  # someone rewrites history
    lines[1] = json.dumps(record)
    path.write_text("\n".join(lines) + "\n")
    result = log.verify()
    assert not result.ok and result.line == 2 and "hash mismatch" in result.error


def test_deletion_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = _write(path, 4)
    lines = path.read_text().splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n")
    result = log.verify()
    assert not result.ok and result.line == 2


def test_chain_continues_across_instances(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write(path, 2)
    second = AuditLog(path)
    record = second.append({"tool": "x", "decision": "allow"})
    assert record["seq"] == 3
    assert second.verify().ok


def test_concurrent_appends_keep_the_chain_valid(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"

    def worker(n: int) -> None:
        log = AuditLog(path)  # separate instances, like the server and the CLI
        for i in range(20):
            log.append({"tool": "t", "decision": "allow", "worker": n, "i": i})

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    result = AuditLog(path).verify()
    assert result.ok and result.records == 160


def test_long_last_line_is_read_correctly(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append({"tool": "t", "decision": "allow", "blob": "x" * 50_000})
    assert log.append({"tool": "t", "decision": "allow"})["seq"] == 2
    assert log.verify().ok
