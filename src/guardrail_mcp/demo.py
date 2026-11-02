"""`guardrail-mcp demo`: a scripted agent session against an in-memory GitHub.

No token, no network. It shows every guardrail firing once, then verifies the
audit log. Useful for evaluating the project in a minute and for recordings.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

import anyio
from mcp import Client

from .catalog import READ_TOOLS
from .cli import decide_approval
from .fake_github import demo_github
from .github import GitHubClient
from .policy import policy_from_dict
from .server import build_server

DEMO_POLICY: dict[str, Any] = {
    "repos": {"allow": ["acme/web-app"]},
    "tools": {
        "allow": [*READ_TOOLS, "create_issue", "comment_on_issue", "add_labels", "create_branch",
                  "commit_file", "open_pull_request", "rerun_failed_jobs"],
        "require_approval": ["close_issue"],
        # merge_pull_request is not listed, so the agent never even sees it.
    },
    "limits": {"max_writes_per_session": 10},
}

_TAGS = {
    "allow": ("ALLOW", "32"), "deny": ("DENY", "31"), "dry_run": ("DRY RUN", "36"), "approval": ("APPROVAL", "33"),
    "replay": ("REPLAY", "35"), "hidden": ("HIDDEN", "31"), "human": ("APPROVED", "32"),
}


class _Printer:
    def __init__(self) -> None:
        self.color = sys.stdout.isatty()
        try:
            "→".encode(sys.stdout.encoding or "utf-8")
            self.arrow = "→"
        except (UnicodeEncodeError, LookupError):
            self.arrow = "->"

    def line(self, actor: str, call: str, tag: str, detail: str) -> None:
        label, code = _TAGS[tag]
        badge = f"[{label}]".ljust(11)
        if self.color:
            badge = f"\033[{code}m{badge}\033[0m"
        print(f"  {actor:<5} {self.arrow} {call:<54} {badge} {detail}")


def _call_repr(tool: str, args: dict[str, Any]) -> str:
    shown = {k: v for k, v in args.items() if k not in ("content", "body", "message", "title") or k == "title"}
    parts = ", ".join(f"{k}={json.dumps(v)}" for k, v in shown.items() if k != "repo")
    text = f"{tool}({parts})"
    return text if len(text) <= 54 else text[:51] + "..."


def _rule(text: str) -> str:
    match = re.search(r"\[([a-z_.]+)\]", text)
    return match.group(1) if match else text[:60]


async def _session(workdir: Path) -> int:
    fake = demo_github()
    policy = policy_from_dict(DEMO_POLICY, base_dir=workdir)
    server, guard = build_server(
        policy, github=GitHubClient(None, transport=fake.transport), agent_id="demo-agent"
    )
    out = _Printer()
    repo = "acme/web-app"
    blocked = 0

    print("\nguardrail-mcp demo: an agent fixes a checkout bug under policy (offline, in-memory GitHub)\n")
    print(f"  policy: repos {policy.repos.allow}, writes only on '{policy.branches.agent_prefix}*', "
          f"close_issue needs approval, merge hidden\n")

    async with Client(server) as client:
        listed = {t.name for t in (await client.list_tools()).tools}

        async def call(tool: str, args: dict[str, Any], detail: Any = None, label: str | None = None) -> tuple[str, Any]:
            nonlocal blocked
            result = await client.call_tool(tool, args)
            text = result.content[0].text if result.content else ""
            data = result.structured_content or {}
            call_text = label or _call_repr(tool, args)
            if tool not in listed:
                blocked += 1
                out.line("agent", call_text, "hidden", "not exposed by policy, the agent cannot see or call it")
                return "hidden", data
            if result.is_error and "APPROVAL REQUIRED" in text:
                approval_id = re.search(r"(apr_[0-9a-f]+)", text).group(1)
                out.line("agent", call_text, "approval", f"paused, request {approval_id} waits for a human")
                return approval_id, data
            if result.is_error:
                blocked += 1
                out.line("agent", call_text, "deny", _rule(text))
                return "deny", data
            if data.get("status") == "dry_run":
                out.line("agent", call_text, "dry_run", "preview returned, nothing changed")
                return "dry_run", data
            if data.get("idempotent_replay"):
                out.line("agent", call_text, "replay", "original result returned, no duplicate PR")
                return "replay", data
            out.line("agent", call_text, "allow", detail(data) if callable(detail) else (detail or "ok"))
            return "allow", data

        await call("describe_permissions", {}, lambda d: (
            f"{len(d['tools']['allowed'])} tools allowed, {len(d['tools']['require_human_approval'])} gated, "
            f"{len(d['tools']['not_available'])} hidden"))
        await call("list_issues", {"repo": repo}, lambda d: f"{d['count']} open issues")
        await call("get_file", {"repo": repo, "path": "config/settings.py"},
                   lambda d: f"{d.get('_guardrail', {}).get('redacted_secrets', 0)} credential redacted before reaching the model")
        await call("get_file", {"repo": repo, "path": ".env"})
        await call("create_issue", {"repo": "acme/billing", "title": "Rotate keys"},
                   label='create_issue(repo="acme/billing")')
        await call("commit_file", {"repo": repo, "branch": "main", "path": "src/checkout.py",
                                   "content": "x", "message": "hotfix"})

        branch = "agent/fix-double-submit"
        await call("create_branch", {"repo": repo, "branch": branch}, "branch created from main")
        await call("commit_file", {"repo": repo, "branch": branch, "path": ".github/workflows/deploy.yml",
                                   "content": "on: push", "message": "speed up deploys"},
                   label='commit_file(path=".github/workflows/deploy.yml")')

        fix = ("def submit_order(cart):\n"
               "    return api.post('/orders', cart, idempotency_key=cart.id)\n")
        await call("commit_file", {"repo": repo, "branch": branch, "path": "src/checkout.py", "content": fix,
                                   "message": "Make order submission idempotent (#1)"},
                   lambda d: f"commit {d.get('commit_sha', '')[:7]} on {branch}",
                   label='commit_file(path="src/checkout.py")')

        token = "gh" + "p_" + "Z" * 36  # assembled at runtime, never a literal in the repo
        await call("comment_on_issue", {"repo": repo, "number": 1, "body": f"Debug with token {token}"},
                   label='comment_on_issue(number=1, body="...ghp_ZZZZ...")')

        pr = {"repo": repo, "head": branch, "base": "main", "title": "Fix double submit at checkout",
              "body": "Closes #1", "draft": False}
        await call("open_pull_request", {**pr, "dry_run": True}, label="open_pull_request(dry_run=true)")
        _, opened = await call("open_pull_request", pr, lambda d: f"PR #{d['number']} opened as draft (policy)",
                               label="open_pull_request(head=\"agent/fix-double-submit\")")
        writes_before = len(fake.writes)
        await call("open_pull_request", pr, label="open_pull_request(...)  # agent retries")
        assert len(fake.writes) == writes_before, "a replay must never reach GitHub"

        close = {"repo": repo, "number": 1, "reason": "completed", "comment": f"Fixed in #{opened.get('number')}"}
        approval_id, _ = await call("close_issue", close, label="close_issue(number=1)")
        decide_approval(policy, guard.state, approval_id, approve=True, by="maintainer")
        out.line("human", f"guardrail-mcp approvals approve {approval_id}", "human", "single use, logged with who approved")
        await call("close_issue", close, lambda d: f"issue #1 is {d['state']}", label="close_issue(number=1)  # same args")
        await call("merge_pull_request", {"repo": repo, "number": opened.get("number", 1)})
        await call("get_ci_status", {"repo": repo, "ref": "main"}, lambda d: f"{d['overall']}: " + (
            ", ".join(f"{c['name']} (run {c['run_id']})" for c in d["failing"]) or "nothing failing"))

    verified = guard.audit.verify()
    real_writes = len(fake.writes)
    print()
    print(f"  {blocked} actions blocked before reaching GitHub, {real_writes} real API writes performed.")
    status = "intact" if verified.ok else f"BROKEN at line {verified.line}: {verified.error}"
    print(f"  audit log: {verified.records} records, hash chain {status}")
    return 0 if verified.ok else 1


def run_demo(keep: bool = False) -> int:
    workdir = Path(tempfile.mkdtemp(prefix="guardrail-demo-"))
    logging.disable(logging.INFO)  # keep the walkthrough readable; denials are shown inline
    try:
        code = anyio.run(_session, workdir)
        audit_path = workdir / ".guardrail" / "audit.jsonl"
        if keep:
            print(f"  audit file: {audit_path}")
            print(f"  inspect it: guardrail-mcp audit tail -n 40 --policy {workdir / 'policy.yaml'}")
            (workdir / "policy.yaml").write_text(json.dumps(DEMO_POLICY, indent=2), encoding="utf-8")
        else:
            print("  run `guardrail-mcp demo --keep` to keep the audit file and inspect it.")
        print()
        return code
    finally:
        logging.disable(logging.NOTSET)
        if not keep:
            shutil.rmtree(workdir, ignore_errors=True)
