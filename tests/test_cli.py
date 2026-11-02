from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
import yaml
from mcp import Client, StdioServerParameters

from guardrail_mcp.cli import main
from guardrail_mcp.state import StateStore

from .conftest import BASE_POLICY


@pytest.fixture
def policy_file(tmp_path: Path) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(BASE_POLICY), encoding="utf-8")
    return path


def test_check_prints_effective_permissions(policy_file: Path, capsys) -> None:
    assert main(["check", "--policy", str(policy_file)]) == 0
    out = capsys.readouterr().out
    assert "needs approval:  close_issue" in out
    assert "hidden:          merge_pull_request" in out


def test_check_rejects_invalid_policy(tmp_path: Path) -> None:
    bad = tmp_path / "policy.yaml"
    bad.write_text("tools:\n  allow: [rm_rf]\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        main(["check", "--policy", str(bad)])
    assert "unknown tool" in str(exc.value)


def test_approve_from_the_cli(policy_file: Path, capsys) -> None:
    store = StateStore(policy_file.parent / ".guardrail" / "state.db")
    request = store.request_approval(args_hash="h", tool="close_issue", repo="acme/web-app",
                                     args={"number": 1}, ttl=600, session="s_test")
    assert main(["approvals", "list", "--policy", str(policy_file)]) == 0
    assert request.id in capsys.readouterr().out

    assert main(["approvals", "approve", request.id, "--by", "lead", "--policy", str(policy_file)]) == 0
    assert store.get_approval(request.id).status == "approved"
    assert main(["approvals", "approve", request.id, "--policy", str(policy_file)]) == 1  # already decided

    assert main(["audit", "verify", "--policy", str(policy_file)]) == 0
    assert main(["audit", "tail", "--policy", str(policy_file)]) == 0
    assert "approval_granted" in capsys.readouterr().out


def test_audit_verify_fails_on_tampering(policy_file: Path, capsys) -> None:
    store = StateStore(policy_file.parent / ".guardrail" / "state.db")
    for i in range(2):
        req = store.request_approval(args_hash=f"h{i}", tool="close_issue", repo="acme/web-app",
                                     args={"number": i}, ttl=600, session="s")
        main(["approvals", "approve", req.id, "--policy", str(policy_file)])
    audit = policy_file.parent / ".guardrail" / "audit.jsonl"
    lines = audit.read_text().splitlines()
    record = json.loads(lines[0])
    record["actor"] = "someone-else"
    lines[0] = json.dumps(record)
    audit.write_text("\n".join(lines) + "\n")
    assert main(["audit", "verify", "--policy", str(policy_file)]) == 1


@pytest.mark.anyio
async def test_real_stdio_server_starts_and_answers(policy_file: Path) -> None:
    env = {k: v for k, v in os.environ.items() if k not in ("GITHUB_TOKEN", "GH_TOKEN")}
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "guardrail_mcp", "serve", "--policy", str(policy_file)], env=env
    )
    async with Client(params) as client:
        names = {t.name for t in (await client.list_tools()).tools}
        assert "commit_file" in names and "merge_pull_request" not in names
        result = await client.call_tool("describe_permissions", {})
        assert not result.is_error
        assert result.structured_content["branches"]["you_may_write_to"] == "agent/*"
