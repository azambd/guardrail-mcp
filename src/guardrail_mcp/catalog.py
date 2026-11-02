"""The tool catalog: every tool the server knows about, and what the guard
needs to know about each one before it runs.

Keeping this metadata separate from the tool functions means the policy can be
validated (unknown tool names are rejected) without importing any network code,
and the guard can reason about a call without knowing how it is executed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from mcp_types import ToolAnnotations

Kind = Literal["read", "write", "meta"]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    kind: Kind
    title: str
    #: MCP hint: the tool may destroy or irreversibly change data.
    destructive: bool = False
    #: MCP hint: calling twice with the same arguments has no extra effect.
    idempotent: bool = True
    #: Argument that names the target repository (``owner/name``).
    repo_arg: str | None = "repo"
    #: Arguments naming a branch the agent writes to (checked against branch rules).
    branch_args: tuple[str, ...] = ()
    #: Arguments naming a file path (checked against path rules).
    path_args: tuple[str, ...] = ()
    #: Free-text arguments (length capped, scanned for secrets).
    text_args: tuple[str, ...] = ()
    #: File-content arguments (size capped, scanned for secrets).
    file_args: tuple[str, ...] = ()
    #: Argument naming a pull request base branch.
    base_arg: str | None = None

    @property
    def is_write(self) -> bool:
        return self.kind == "write"

    def annotations(self) -> ToolAnnotations:
        read_only = self.kind != "write"
        return ToolAnnotations(
            title=self.title,
            read_only_hint=read_only,
            destructive_hint=None if read_only else self.destructive,
            idempotent_hint=None if read_only else self.idempotent,
            open_world_hint=self.kind != "meta",
        )


_SPECS: list[ToolSpec] = [
    # Meta: always exposed so the agent can see its own boundaries.
    ToolSpec("describe_permissions", "meta", "Describe my permissions", repo_arg=None),
    # Reads
    ToolSpec("get_repo", "read", "Get repository"),
    ToolSpec("list_issues", "read", "List issues"),
    ToolSpec("get_issue", "read", "Get issue with comments"),
    ToolSpec("search_code", "read", "Search code"),
    ToolSpec("get_file", "read", "Read file", path_args=("path",)),
    ToolSpec("list_pull_requests", "read", "List pull requests"),
    ToolSpec("get_pull_request", "read", "Get pull request"),
    ToolSpec("get_ci_status", "read", "Get CI status"),
    # Writes
    ToolSpec("create_issue", "write", "Create issue", idempotent=False, text_args=("title", "body")),
    ToolSpec("comment_on_issue", "write", "Comment on issue or PR", idempotent=False, text_args=("body",)),
    ToolSpec("add_labels", "write", "Add labels", text_args=("labels",)),
    ToolSpec("close_issue", "write", "Close issue", text_args=("comment",)),
    ToolSpec("create_branch", "write", "Create branch", branch_args=("branch",)),
    ToolSpec(
        "commit_file",
        "write",
        "Commit file to branch",
        idempotent=False,
        branch_args=("branch",),
        path_args=("path",),
        text_args=("message",),
        file_args=("content",),
    ),
    ToolSpec(
        "open_pull_request",
        "write",
        "Open pull request",
        idempotent=False,
        branch_args=("head",),
        text_args=("title", "body"),
        base_arg="base",
    ),
    ToolSpec("merge_pull_request", "write", "Merge pull request", destructive=True, idempotent=False),
    ToolSpec("rerun_failed_jobs", "write", "Re-run failed CI jobs", idempotent=False),
]

CATALOG: dict[str, ToolSpec] = {spec.name: spec for spec in _SPECS}
READ_TOOLS = [s.name for s in _SPECS if s.kind == "read"]
WRITE_TOOLS = [s.name for s in _SPECS if s.kind == "write"]
