"""Assemble the MCP server from a policy."""

from __future__ import annotations

import os

from mcp.server.mcpserver import MCPServer

from . import __version__
from .audit import AuditLog
from .github import GitHubClient
from .guard import Guard
from .policy import Policy
from .state import StateStore
from .tools import build_tools


def _instructions(policy: Policy) -> str:
    gated = ", ".join(policy.tools.require_approval) or "none"
    return (
        "You are working through a policy-enforced GitHub gateway. Every call, including denied ones, is "
        "recorded in an audit log. Call describe_permissions first to see the repositories, tools, branches "
        f"and paths you may use. Write only to branches starting with {policy.branches.agent_prefix!r}. "
        f"Tools that need human approval: {gated}. When a call is denied, do not look for a workaround; "
        "explain the denial to the user. Use dry_run=true to preview a write before making it."
    )


def build_server(
    policy: Policy,
    *,
    github: GitHubClient | None = None,
    agent_id: str = "agent",
    session_id: str | None = None,
) -> tuple[MCPServer, Guard]:
    """Build the server. Tools the policy does not enable are never registered,
    so the agent cannot see them, let alone call them."""
    guard = Guard(
        policy,
        AuditLog(policy.audit_path),
        StateStore(policy.state_path),
        agent_id=agent_id,
        session_id=session_id,
    )
    gh = github or GitHubClient(token=os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"))

    server = MCPServer(
        name="guardrail-mcp",
        title="Guardrail MCP for GitHub",
        version=__version__,
        instructions=_instructions(policy),
    )
    for fn, spec in build_tools(guard, gh):
        permission = policy.permission(spec.name)
        if permission == "deny":
            continue
        description = (fn.__doc__ or "").strip()
        if permission == "approval":
            description += " Requires human approval: the first call returns an approval request id."
        server.add_tool(fn, name=spec.name, title=spec.title, description=description, annotations=spec.annotations())
    return server, guard
