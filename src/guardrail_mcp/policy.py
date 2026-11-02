"""Policy model: what the agent is allowed to do, loaded from YAML.

The policy is the contract between the humans who own the repositories and the
agent that works in them. It is validated strictly (unknown keys and unknown
tool names are errors), so a typo can never silently widen access.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_validator, model_validator

from .catalog import CATALOG, READ_TOOLS

Permission = Literal["allow", "approval", "deny"]


# --------------------------------------------------------------------------- globs


@lru_cache(maxsize=512)
def _glob_regex(pattern: str, ignore_case: bool) -> re.Pattern[str]:
    """Translate a glob into a regex.

    ``*`` matches within one path segment, ``**`` matches across segments and
    ``**/`` matches zero or more leading directories, so ``**/*.pem`` matches
    both ``key.pem`` and ``certs/prod/key.pem``.
    """
    out: list[str] = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    flags = re.IGNORECASE if ignore_case else 0
    return re.compile("^" + "".join(out) + "$", flags)


def glob_match(value: str, pattern: str, *, ignore_case: bool = False) -> bool:
    return bool(_glob_regex(pattern, ignore_case).match(value))


def first_match(value: str, patterns: list[str], *, ignore_case: bool = False) -> str | None:
    for pattern in patterns:
        if glob_match(value, pattern, ignore_case=ignore_case):
            return pattern
    return None


# --------------------------------------------------------------------------- model


@dataclass(frozen=True)
class Violation:
    """A policy rule that blocks a call. ``rule`` is a stable id for the audit log."""

    rule: str
    message: str


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RepoRules(_Strict):
    allow: list[str] = Field(default_factory=list, description="owner/name globs the agent may touch")
    deny: list[str] = Field(default_factory=list, description="owner/name globs that are always off limits")


class ToolRules(_Strict):
    allow: list[str] = Field(default_factory=lambda: list(READ_TOOLS))
    require_approval: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _known_and_disjoint(self) -> ToolRules:
        for name in [*self.allow, *self.require_approval]:
            if name not in CATALOG:
                raise ValueError(f"unknown tool {name!r}; known tools: {', '.join(sorted(CATALOG))}")
            if CATALOG[name].kind == "meta":
                raise ValueError(f"{name!r} is always available and cannot be configured")
        both = sorted(set(self.allow) & set(self.require_approval))
        if both:
            raise ValueError(f"tools listed in both allow and require_approval: {both}")
        return self


class BranchRules(_Strict):
    agent_prefix: str = Field("agent/", min_length=1)
    protected: list[str] = Field(default_factory=lambda: ["main", "master", "release/*"])


class PathRules(_Strict):
    deny_write: list[str] = Field(
        default_factory=lambda: [".github/workflows/**", ".env", ".env.*", "**/*.pem", "**/*.key"]
    )
    deny_read: list[str] = Field(default_factory=lambda: [".env", ".env.*", "**/*.pem", "**/*.key"])


class PullRequestRules(_Strict):
    force_draft: bool = True
    allowed_bases: list[str] = Field(default_factory=lambda: ["main", "master"])


class Limits(_Strict):
    max_writes_per_session: int = Field(25, ge=0)
    max_text_chars: int = Field(20_000, ge=1)
    max_file_bytes: int = Field(200_000, ge=1)
    idempotency_window_seconds: int = Field(600, ge=0)
    approval_ttl_seconds: int = Field(3600, ge=60)


class ContentRules(_Strict):
    block_secrets: bool = True
    redact_secrets_in_reads: bool = True
    extra_secret_patterns: list[str] = Field(default_factory=list)

    @field_validator("extra_secret_patterns")
    @classmethod
    def _compiles(cls, patterns: list[str]) -> list[str]:
        for p in patterns:
            try:
                re.compile(p)
            except re.error as exc:
                raise ValueError(f"invalid regex {p!r}: {exc}") from exc
        return patterns


class AuditRules(_Strict):
    path: str = ".guardrail/audit.jsonl"
    max_arg_chars: int = Field(300, ge=32)


class StateRules(_Strict):
    path: str = ".guardrail/state.db"


class Policy(_Strict):
    version: Literal[1] = 1
    mode: Literal["live", "dry_run"] = "live"
    repos: RepoRules = Field(default_factory=RepoRules)
    tools: ToolRules = Field(default_factory=ToolRules)
    branches: BranchRules = Field(default_factory=BranchRules)
    paths: PathRules = Field(default_factory=PathRules)
    pull_requests: PullRequestRules = Field(default_factory=PullRequestRules)
    limits: Limits = Field(default_factory=Limits)
    content: ContentRules = Field(default_factory=ContentRules)
    audit: AuditRules = Field(default_factory=AuditRules)
    state: StateRules = Field(default_factory=StateRules)

    _base_dir: Path = PrivateAttr(default_factory=Path.cwd)

    # ---------------------------------------------------------------- paths

    def _resolve(self, value: str) -> Path:
        path = Path(value).expanduser()
        return path if path.is_absolute() else (self._base_dir / path)

    @property
    def audit_path(self) -> Path:
        return self._resolve(self.audit.path)

    @property
    def state_path(self) -> Path:
        return self._resolve(self.state.path)

    # ---------------------------------------------------------------- checks

    def permission(self, tool: str) -> Permission:
        spec = CATALOG.get(tool)
        if spec is None:
            return "deny"
        if spec.kind == "meta":
            return "allow"
        if tool in self.tools.require_approval:
            return "approval"
        if tool in self.tools.allow:
            return "allow"
        return "deny"

    def check_repo(self, repo: str) -> Violation | None:
        parts = repo.split("/")
        if len(parts) != 2 or any(part in ("", ".", "..") for part in parts):
            return Violation("repos.invalid", f"{repo!r} is not a valid owner/name")
        hit = first_match(repo, self.repos.deny, ignore_case=True)
        if hit:
            return Violation("repos.deny", f"repository {repo!r} matches deny rule {hit!r}")
        if not first_match(repo, self.repos.allow, ignore_case=True):
            return Violation("repos.allow", f"repository {repo!r} is not in the allow list")
        return None

    def check_branch(self, branch: str) -> Violation | None:
        hit = first_match(branch, self.branches.protected)
        if hit:
            return Violation("branches.protected", f"branch {branch!r} is protected ({hit!r})")
        if not branch.startswith(self.branches.agent_prefix):
            return Violation(
                "branches.agent_prefix",
                f"the agent may only write to branches starting with {self.branches.agent_prefix!r}, got {branch!r}",
            )
        return None

    def check_path(self, path: str, *, write: bool) -> Violation | None:
        normalized = path.strip().lstrip("/")
        if ".." in normalized.split("/"):
            return Violation("paths.traversal", f"path {path!r} contains '..'")
        rules = self.paths.deny_write if write else self.paths.deny_read
        hit = first_match(normalized, rules)
        if hit:
            rule = "paths.deny_write" if write else "paths.deny_read"
            return Violation(rule, f"path {normalized!r} matches {hit!r}")
        return None

    def check_base(self, base: str) -> Violation | None:
        if not first_match(base, self.pull_requests.allowed_bases):
            return Violation(
                "pull_requests.allowed_bases",
                f"pull requests may only target {self.pull_requests.allowed_bases}, got {base!r}",
            )
        return None

    # ---------------------------------------------------------------- summary

    def describe(self) -> dict[str, Any]:
        """A plain summary of the policy, written for the agent to read."""
        by_permission: dict[str, list[str]] = {"allow": [], "approval": [], "deny": []}
        for name, spec in CATALOG.items():
            if spec.kind != "meta":
                by_permission[self.permission(name)].append(name)
        return {
            "mode": self.mode,
            "repositories": {"allow": self.repos.allow, "deny": self.repos.deny},
            "tools": {
                "allowed": by_permission["allow"],
                "require_human_approval": by_permission["approval"],
                "not_available": by_permission["deny"],
            },
            "branches": {
                "you_may_write_to": f"{self.branches.agent_prefix}*",
                "protected": self.branches.protected,
            },
            "paths": {"never_write": self.paths.deny_write, "never_read": self.paths.deny_read},
            "pull_requests": {
                "always_draft": self.pull_requests.force_draft,
                "allowed_bases": self.pull_requests.allowed_bases,
            },
            "limits": self.limits.model_dump(),
            "secrets": {
                "writes_containing_secrets_blocked": self.content.block_secrets,
                "secrets_redacted_from_reads": self.content.redact_secrets_in_reads,
            },
            "audit": "Every call, including denials, is recorded in a hash-chained audit log.",
        }


def load_policy(path: str | Path) -> Policy:
    path = Path(path).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"policy file not found: {path}")
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: policy must be a YAML mapping")
    policy = Policy.model_validate(raw)
    policy._base_dir = path.parent
    return policy


def policy_from_dict(data: dict[str, Any], base_dir: str | Path | None = None) -> Policy:
    policy = Policy.model_validate(data)
    if base_dir is not None:
        policy._base_dir = Path(base_dir)
    return policy
