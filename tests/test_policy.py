from pathlib import Path

import pytest
from pydantic import ValidationError

from guardrail_mcp.policy import glob_match, load_policy, policy_from_dict

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    ("value", "pattern", "expected"),
    [
        ("key.pem", "**/*.pem", True),
        ("certs/prod/key.pem", "**/*.pem", True),
        ("key.pem.txt", "**/*.pem", False),
        (".github/workflows/ci.yml", ".github/workflows/**", True),
        (".github/CODEOWNERS", ".github/workflows/**", False),
        ("release/1.2", "release/*", True),
        ("release/1/2", "release/*", False),
        (".env.local", ".env.*", True),
        ("config/.env", ".env", False),
    ],
)
def test_glob_match(value: str, pattern: str, expected: bool) -> None:
    assert glob_match(value, pattern) is expected


def test_repo_rules_deny_wins_and_match_is_case_insensitive() -> None:
    policy = policy_from_dict({"repos": {"allow": ["acme/*"], "deny": ["acme/billing"]}})
    assert policy.check_repo("ACME/Web-App") is None
    assert policy.check_repo("acme/billing").rule == "repos.deny"
    assert policy.check_repo("other/repo").rule == "repos.allow"
    assert policy.check_repo("acme/..").rule == "repos.invalid"


def test_empty_allow_list_denies_everything() -> None:
    assert policy_from_dict({}).check_repo("acme/web-app").rule == "repos.allow"


def test_branch_rules() -> None:
    policy = policy_from_dict({})
    assert policy.check_branch("agent/fix-1") is None
    assert policy.check_branch("main").rule == "branches.protected"
    assert policy.check_branch("release/2.0").rule == "branches.protected"
    assert policy.check_branch("feature/x").rule == "branches.agent_prefix"


def test_path_rules() -> None:
    policy = policy_from_dict({})
    assert policy.check_path("src/app.py", write=True) is None
    assert policy.check_path("/.github/workflows/deploy.yml", write=True).rule == "paths.deny_write"
    assert policy.check_path(".github/workflows/deploy.yml", write=False) is None
    assert policy.check_path("deploy/keys/server.key", write=False).rule == "paths.deny_read"
    assert policy.check_path("src/../.env", write=False).rule == "paths.traversal"


def test_permissions() -> None:
    policy = policy_from_dict({"tools": {"allow": ["get_repo"], "require_approval": ["merge_pull_request"]}})
    assert policy.permission("get_repo") == "allow"
    assert policy.permission("merge_pull_request") == "approval"
    assert policy.permission("commit_file") == "deny"
    assert policy.permission("describe_permissions") == "allow"
    assert policy.permission("not_a_tool") == "deny"


@pytest.mark.parametrize(
    "data",
    [
        {"tools": {"allow": ["delete_repo"]}},
        {"tools": {"allow": ["close_issue"], "require_approval": ["close_issue"]}},
        {"tools": {"allow": ["describe_permissions"]}},
        {"repo": {"allow": []}},
        {"mode": "yolo"},
        {"content": {"extra_secret_patterns": ["("]}},
    ],
)
def test_invalid_policies_are_rejected(data: dict) -> None:
    with pytest.raises((ValidationError, ValueError)):
        policy_from_dict(data)


def test_example_policy_loads_and_paths_resolve_next_to_it() -> None:
    policy = load_policy(ROOT / "policy.example.yaml")
    assert policy.permission("merge_pull_request") == "deny"
    assert policy.permission("close_issue") == "approval"
    assert policy.audit_path == ROOT / ".guardrail" / "audit.jsonl"
