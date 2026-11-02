"""End-to-end: a real MCP client talks to the server, which talks to a fake GitHub."""

from __future__ import annotations

from typing import Any

import pytest
from mcp import Client

from guardrail_mcp.cli import decide_approval

from .conftest import fake_token

pytestmark = pytest.mark.anyio

REPO = "acme/web-app"


async def call(env, tool: str, args: dict[str, Any]):
    async with Client(env.server) as client:
        result = await client.call_tool(tool, args)
    text = result.content[0].text if result.content else ""
    return result.is_error, (result.structured_content or {}), text


# ------------------------------------------------------------------ exposure


async def test_only_enabled_tools_are_listed_with_correct_hints(make_env) -> None:
    env = make_env()
    async with Client(env.server) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
    assert "merge_pull_request" not in tools
    assert "describe_permissions" in tools
    assert tools["get_repo"].annotations.read_only_hint is True
    assert tools["commit_file"].annotations.read_only_hint is False
    assert "Requires human approval" in tools["close_issue"].description


async def test_hidden_tool_cannot_be_called(make_env) -> None:
    env = make_env()
    is_error, _, text = await call(env, "merge_pull_request", {"repo": REPO, "number": 1})
    assert is_error and "Unknown tool" in text
    assert env.fake.calls == []


async def test_describe_permissions(make_env) -> None:
    env = make_env(limits={"max_writes_per_session": 7})
    is_error, data, _ = await call(env, "describe_permissions", {})
    assert not is_error
    assert data["tools"]["require_human_approval"] == ["close_issue"]
    assert "merge_pull_request" in data["tools"]["not_available"]
    assert data["branches"]["you_may_write_to"] == "agent/*"
    assert data["session"]["writes_remaining"] == 7


# ------------------------------------------------------------------ reads


async def test_read_is_allowed_and_audited(make_env) -> None:
    env = make_env()
    is_error, data, _ = await call(env, "list_issues", {"repo": REPO})
    assert not is_error and data["count"] == 3
    record = env.last_record()
    assert record["tool"] == "list_issues" and record["decision"] == "allow" and record["outcome"] == "ok"


async def test_secrets_are_redacted_from_reads(make_env) -> None:
    env = make_env()
    is_error, data, _ = await call(env, "get_file", {"repo": REPO, "path": "config/settings.py"})
    assert not is_error
    assert "[REDACTED:aws_access_key_id]" in data["content"]
    assert data["_guardrail"]["redacted_secrets"] == 1


async def test_secret_files_cannot_be_read(make_env) -> None:
    env = make_env()
    is_error, _, text = await call(env, "get_file", {"repo": REPO, "path": ".env"})
    assert is_error and "paths.deny_read" in text
    assert env.fake.calls == []


async def test_github_errors_come_back_as_clear_tool_errors(make_env) -> None:
    env = make_env()
    is_error, _, text = await call(env, "get_issue", {"repo": REPO, "number": 999})
    assert is_error and "GitHub 404" in text and "Hint" in text
    assert env.last_record()["outcome"] == "error"


async def test_ci_status_exposes_run_ids(make_env) -> None:
    env = make_env()
    _, data, _ = await call(env, "get_ci_status", {"repo": REPO, "ref": "main"})
    assert data["overall"] == "failure"
    assert data["failing"][0]["run_id"] == 9001


# ------------------------------------------------------------------ denials


@pytest.mark.parametrize(
    ("tool", "args", "rule"),
    [
        ("create_issue", {"repo": "acme/billing", "title": "x"}, "repos.allow"),
        ("create_branch", {"repo": REPO, "branch": "feature/x"}, "branches.agent_prefix"),
        ("create_branch", {"repo": REPO, "branch": "main"}, "branches.protected"),
        ("commit_file", {"repo": REPO, "branch": "agent/a", "path": ".github/workflows/ci.yml",
                         "content": "x", "message": "m"}, "paths.deny_write"),
        ("open_pull_request", {"repo": REPO, "head": "release/1", "base": "main", "title": "t"},
         "branches.protected"),
        ("open_pull_request", {"repo": REPO, "head": "agent/a", "base": "develop", "title": "t"},
         "pull_requests.allowed_bases"),
        ("comment_on_issue", {"repo": REPO, "number": 1, "body": "x" * 20_001}, "limits.max_text_chars"),
    ],
)
async def test_policy_denials_never_reach_github(make_env, tool, args, rule) -> None:
    env = make_env()
    is_error, _, text = await call(env, tool, args)
    assert is_error and f"[{rule}]" in text
    assert env.fake.calls == []
    record = env.last_record()
    assert record["decision"] == "deny" and record["rule"] == rule


async def test_credentials_in_writes_are_blocked_and_never_logged(make_env) -> None:
    env = make_env()
    token = fake_token()
    is_error, _, text = await call(env, "comment_on_issue", {"repo": REPO, "number": 1, "body": f"use {token}"})
    assert is_error and "content.block_secrets" in text
    assert env.fake.writes == []
    assert token not in env.audit_text()
    assert "[REDACTED:github_token]" in env.audit_text()


# ------------------------------------------------------------------ write safety


async def test_dry_run_changes_nothing(make_env) -> None:
    env = make_env()
    is_error, data, _ = await call(env, "create_issue", {"repo": REPO, "title": "x", "dry_run": True})
    assert not is_error and data["status"] == "dry_run"
    assert data["would_perform"]["method"] == "POST"
    assert env.fake.writes == []


async def test_global_dry_run_mode(make_env) -> None:
    env = make_env(mode="dry_run")
    _, data, _ = await call(env, "create_branch", {"repo": REPO, "branch": "agent/x"})
    assert data["status"] == "dry_run" and "dry_run mode" in data["note"]
    assert env.fake.writes == []


async def test_identical_retry_is_replayed_not_repeated(make_env) -> None:
    env = make_env()
    args = {"repo": REPO, "title": "Bug", "body": "details"}
    _, first, _ = await call(env, "create_issue", args)
    _, second, _ = await call(env, "create_issue", args)
    assert second["idempotent_replay"] is True and second["number"] == first["number"]
    assert len(env.fake.writes) == 1
    _, third, _ = await call(env, "create_issue", {**args, "title": "Another bug"})
    assert third["number"] != first["number"] and len(env.fake.writes) == 2


async def test_write_budget(make_env) -> None:
    env = make_env(limits={"max_writes_per_session": 2})
    for i in range(2):
        is_error, _, _ = await call(env, "create_issue", {"repo": REPO, "title": f"t{i}"})
        assert not is_error
    is_error, _, text = await call(env, "create_issue", {"repo": REPO, "title": "t3"})
    assert is_error and "limits.max_writes_per_session" in text
    assert len(env.fake.writes) == 2


async def test_pull_requests_are_forced_to_draft(make_env) -> None:
    env = make_env()
    await call(env, "create_branch", {"repo": REPO, "branch": "agent/x"})
    await call(env, "commit_file", {"repo": REPO, "branch": "agent/x", "path": "a.txt", "content": "hi", "message": "m"})
    _, data, _ = await call(env, "open_pull_request", {"repo": REPO, "head": "agent/x", "title": "t", "draft": False})
    assert data["draft"] is True and "policy_note" in data


async def test_full_branch_commit_pr_flow(make_env) -> None:
    env = make_env()
    _, branch, _ = await call(env, "create_branch", {"repo": REPO, "branch": "agent/fix"})
    assert branch["from"] == "main"
    _, created, _ = await call(env, "commit_file", {"repo": REPO, "branch": "agent/fix", "path": "src/new.py",
                                                    "content": "print(1)\n", "message": "add"})
    assert created["created"] is True
    _, updated, _ = await call(env, "commit_file", {"repo": REPO, "branch": "agent/fix", "path": "src/checkout.py",
                                                    "content": "fixed\n", "message": "fix"})
    assert updated["created"] is False
    _, pr, _ = await call(env, "open_pull_request", {"repo": REPO, "head": "agent/fix", "title": "Fix"})
    _, detail, _ = await call(env, "get_pull_request", {"repo": REPO, "number": pr["number"]})
    assert {f["path"] for f in detail["changed_files"]} == {"src/new.py", "src/checkout.py"}


async def test_unloggable_writes_do_not_happen(make_env) -> None:
    env = make_env()
    broken = env.workdir / "audit-is-a-directory"
    broken.mkdir()
    env.guard.audit.path = broken
    is_error, _, text = await call(env, "create_issue", {"repo": REPO, "title": "x"})
    assert is_error and "audit log could not be written" in text
    assert env.fake.writes == []


# ------------------------------------------------------------------ approvals


async def test_approval_flow(make_env) -> None:
    env = make_env()
    args = {"repo": REPO, "number": 1, "reason": "completed"}

    is_error, _, text = await call(env, "close_issue", args)
    assert is_error and "APPROVAL REQUIRED" in text
    pending = env.guard.state.list_approvals("pending")
    assert len(pending) == 1
    approval_id = pending[0].id

    # Asking again does not open a second request.
    _, _, text = await call(env, "close_issue", args)
    assert approval_id in text and len(env.guard.state.list_approvals("pending")) == 1
    assert env.fake.writes == []

    # Different arguments are a different request: approval is bound to exact args.
    await call(env, "close_issue", {**args, "number": 2})
    assert len(env.guard.state.list_approvals("pending")) == 2

    decide_approval(env.policy, env.guard.state, approval_id, approve=True, by="reviewer")
    is_error, data, _ = await call(env, "close_issue", args)
    assert not is_error and data["state"] == "closed"
    assert env.guard.state.get_approval(approval_id).status == "consumed"

    records = env.guard.audit.records()
    granted = [r for r in records if r["decision"] == "approval_granted"]
    assert granted and granted[0]["actor"] == "reviewer"
    assert env.guard.audit.verify().ok


async def test_denied_approval_does_not_unlock(make_env) -> None:
    env = make_env()
    args = {"repo": REPO, "number": 1}
    await call(env, "close_issue", args)
    approval_id = env.guard.state.list_approvals("pending")[0].id
    decide_approval(env.policy, env.guard.state, approval_id, approve=False, by="reviewer")
    is_error, _, text = await call(env, "close_issue", args)
    assert is_error and "APPROVAL REQUIRED" in text and approval_id not in text
    assert env.fake.writes == []


async def test_audit_chain_is_valid_after_a_session(make_env) -> None:
    env = make_env()
    await call(env, "list_issues", {"repo": REPO})
    await call(env, "create_issue", {"repo": "acme/billing", "title": "x"})
    await call(env, "create_issue", {"repo": REPO, "title": "x", "dry_run": True})
    await call(env, "create_issue", {"repo": REPO, "title": "x"})
    result = env.guard.audit.verify()
    assert result.ok and result.records == 5  # read, deny, dry run, write intent + result


async def test_decisions_are_attached_to_the_open_telemetry_span(make_env, monkeypatch) -> None:
    from guardrail_mcp import guard as guard_module

    class RecordingSpan:
        def __init__(self) -> None:
            self.events: list[tuple[str, dict]] = []

        def is_recording(self) -> bool:
            return True

        def add_event(self, name: str, attributes: dict) -> None:
            self.events.append((name, attributes))

        def __getattr__(self, _name: str):  # anything else the SDK calls is a no-op
            return lambda *args, **kwargs: None

    span = RecordingSpan()
    monkeypatch.setattr(guard_module._otel_trace, "get_current_span", lambda *args, **kwargs: span)
    env = make_env()
    await call(env, "create_issue", {"repo": "acme/billing", "title": "x"})
    name, attrs = span.events[-1]
    assert name == "guardrail.decision"
    assert attrs["guardrail.decision"] == "deny" and attrs["guardrail.rule"] == "repos.allow"
