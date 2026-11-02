from __future__ import annotations

import copy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from mcp.server.mcpserver import MCPServer

from guardrail_mcp.catalog import READ_TOOLS
from guardrail_mcp.fake_github import FakeGitHub, demo_github
from guardrail_mcp.github import GitHubClient
from guardrail_mcp.guard import Guard
from guardrail_mcp.policy import Policy, policy_from_dict
from guardrail_mcp.server import build_server

BASE_POLICY: dict[str, Any] = {
    "repos": {"allow": ["acme/web-app"]},
    "tools": {
        "allow": [*READ_TOOLS, "create_issue", "comment_on_issue", "add_labels", "create_branch",
                  "commit_file", "open_pull_request", "rerun_failed_jobs"],
        "require_approval": ["close_issue"],
    },
}


@dataclass
class Env:
    policy: Policy
    fake: FakeGitHub
    server: MCPServer
    guard: Guard
    workdir: Path

    def audit_text(self) -> str:
        path = self.policy.audit_path
        return path.read_text(encoding="utf-8") if path.exists() else ""

    def last_record(self) -> dict[str, Any]:
        return self.guard.audit.records()[-1]


def _merge(base: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def make_env(tmp_path: Path):
    def factory(**overrides: Any) -> Env:
        policy = policy_from_dict(_merge(BASE_POLICY, overrides), base_dir=tmp_path)
        fake = demo_github()
        server, guard = build_server(policy, github=GitHubClient(None, transport=fake.transport), agent_id="test")
        return Env(policy, fake, server, guard, tmp_path)

    return factory


def fake_token() -> str:
    """A credential-shaped string built at runtime so no secret literal lives in the repo."""
    return "gh" + "p_" + "A1b2C3d4" * 5
