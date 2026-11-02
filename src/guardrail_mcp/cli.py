"""Command line: run the server, approve requests, inspect and verify the audit log."""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from . import __version__
from .audit import AuditLog
from .policy import Policy, load_policy
from .state import Approval, StateStore

_COLORS = {"allow": "32", "ok": "32", "deny": "31", "error": "31", "dry_run": "36", "approval_required": "33",
           "replayed": "35", "redacted": "35", "approval_granted": "32", "approval_denied": "31"}


def _paint(text: str, key: str, enabled: bool) -> str:
    code = _COLORS.get(key)
    return f"\033[{code}m{text}\033[0m" if enabled and code else text


def _policy_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--policy",
        default=os.environ.get("GUARDRAIL_POLICY", "policy.yaml"),
        help="path to the policy YAML (default: $GUARDRAIL_POLICY or ./policy.yaml)",
    )


def _load(path: str) -> Policy:
    try:
        return load_policy(path)
    except FileNotFoundError as exc:
        raise SystemExit(f"error: {exc}. Copy policy.example.yaml to policy.yaml to start.") from exc
    except ValidationError as exc:
        raise SystemExit(f"error: invalid policy {path}:\n{exc}") from exc



def decide_approval(policy: Policy, store: StateStore, approval_id: str, *, approve: bool, by: str) -> Approval:
    """Record a human decision in the state store and the audit log."""
    approval = store.decide(approval_id, approve=approve, by=by)
    AuditLog(policy.audit_path).append({
        "session": approval.session, "agent": "human", "actor": by, "tool": approval.tool, "kind": "approval",
        "repo": approval.repo, "decision": "approval_granted" if approve else "approval_denied",
        "approval_id": approval.id, "args": approval.args, "args_sha256": approval.args_hash,
    })
    return approval


# ------------------------------------------------------------------ commands


def cmd_serve(args: argparse.Namespace) -> int:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx2").setLevel(logging.WARNING)  # one line per HTTP call is noise on stderr
    log = logging.getLogger("guardrail_mcp")
    policy = _load(args.policy)

    from .server import build_server  # imported here so `--help` stays fast

    if not (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")):
        log.warning("GITHUB_TOKEN is not set: only public repositories can be read and every write will fail")
    server, guard = build_server(policy, agent_id=args.agent_id)
    log.info(
        "guardrail-mcp %s: session %s, mode=%s, audit=%s", __version__, guard.session_id, policy.mode, policy.audit_path
    )
    if args.transport == "stdio":
        server.run("stdio")
    else:
        if args.host not in ("127.0.0.1", "localhost", "::1"):
            log.warning("binding %s exposes the tools to your network with no authentication; put it behind an authenticating proxy", args.host)
        server.run("streamable-http", host=args.host, port=args.port)
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    policy = _load(args.policy)
    summary = policy.describe()
    print(f"Policy OK: {Path(args.policy).resolve()}\n")
    print(f"mode:            {policy.mode}")
    print(f"repositories:    allow {policy.repos.allow or '(none: nothing is reachable)'}; deny {policy.repos.deny or '[]'}")
    print(f"tools allowed:   {', '.join(summary['tools']['allowed']) or '(none)'}")
    print(f"needs approval:  {', '.join(summary['tools']['require_human_approval']) or '(none)'}")
    print(f"hidden:          {', '.join(summary['tools']['not_available']) or '(none)'}")
    print(f"agent branches:  {policy.branches.agent_prefix}*   protected: {', '.join(policy.branches.protected)}")
    print(f"never write:     {', '.join(policy.paths.deny_write)}")
    print(f"never read:      {', '.join(policy.paths.deny_read)}")
    print(f"write budget:    {policy.limits.max_writes_per_session} per session")
    print(f"audit log:       {policy.audit_path}")
    print(f"state db:        {policy.state_path}")
    if not policy.repos.allow:
        print("\nwarning: repos.allow is empty, so every repository call will be denied.")
    return 0


def cmd_approvals(args: argparse.Namespace) -> int:
    policy = _load(args.policy)
    store = StateStore(policy.state_path)
    tty = sys.stdout.isatty()

    if args.action == "list":
        rows = store.list_approvals(None if args.all else "pending")
        if not rows:
            print("No pending approval requests." if not args.all else "No approval requests yet.")
            return 0
        for a in rows:
            expires = "expired" if a.expired and a.status == "pending" else datetime.fromtimestamp(a.expires_at, timezone.utc).strftime("%H:%M UTC")
            print(f"{a.id}  {_paint(a.status, 'approval_required' if a.status == 'pending' else 'ok', tty):<10} "
                  f"{a.tool:<20} {a.repo or '':<28} expires {expires}")
            print(f"    args: {json.dumps(a.args, ensure_ascii=False)[:300]}")
        return 0

    approve = args.action == "approve"
    by = args.by or getpass.getuser()
    try:
        approval = decide_approval(policy, store, args.id, approve=approve, by=by)
    except (KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    verb = "Approved" if approve else "Denied"
    print(f"{verb} {approval.id}: {approval.tool} on {approval.repo} (by {by}).")
    if approve:
        print("The agent can now repeat the call with the same arguments. The approval is single use.")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    policy = _load(args.policy)
    audit = AuditLog(policy.audit_path)
    tty = sys.stdout.isatty()

    if args.action == "verify":
        result = audit.verify()
        if result.ok:
            print(f"Audit log OK: {result.records} records, hash chain intact ({policy.audit_path})")
            return 0
        print(f"Audit log FAILED at line {result.line}: {result.error} ({result.records} valid records before it)")
        return 1

    for r in audit.tail(args.n):
        detail = r.get("rule") or r.get("outcome") or r.get("reason") or ""
        if r.get("approval_id"):
            detail = f"{detail} {r['approval_id']}".strip()
        if r.get("actor"):
            detail = f"{detail} by {r['actor']}"
        phase = f"/{r['phase']}" if r.get("phase") else ""
        print(f"{r['seq']:>5}  {r['ts']}  {_paint(r['decision'] + phase, r['decision'], tty):<26} "
              f"{r['tool']:<20} {r.get('repo') or '':<24} {detail}")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    """Live, read-only check of token, policy and connectivity through the real tool path."""
    import anyio
    from mcp import Client

    from .server import build_server

    logging.disable(logging.INFO)
    policy = _load(args.policy)
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    repo = args.repo or next((r for r in policy.repos.allow if "*" not in r and "?" not in r), None)
    print(f"token:  {'set' if token else 'NOT SET (public repos only, writes will fail)'}")
    print(f"policy: {Path(args.policy).resolve()}  mode={policy.mode}")
    if repo is None:
        print("error: pass --repo owner/name (repos.allow has no exact repository to test)", file=sys.stderr)
        return 1

    server, guard = build_server(policy, agent_id="doctor")
    checks = [
        ("get_repo", {"repo": repo}),
        ("list_issues", {"repo": repo, "limit": 5}),
        ("list_pull_requests", {"repo": repo, "limit": 5}),
    ]
    failures = 0

    async def run() -> None:
        nonlocal failures
        async with Client(server) as client:
            names = {t.name for t in (await client.list_tools()).tools}
            repo_info: dict = {}
            for tool, tool_args in checks:
                if tool not in names:
                    print(f"  skip  {tool:<20} (not enabled by policy)")
                    continue
                result = await client.call_tool(tool, tool_args)
                if result.is_error:
                    failures += 1
                    text = result.content[0].text if result.content else ""
                    print(f"  FAIL  {tool:<20} {text.removeprefix(f'Error executing tool {tool}: ')[:200]}")
                    continue
                data = result.structured_content or {}
                if tool == "get_repo":
                    repo_info = data
                    print(f"  ok    {tool:<20} {data.get('full_name')} (default branch {data.get('default_branch')})")
                else:
                    print(f"  ok    {tool:<20} {data.get('count', 0)} returned")
            branch = repo_info.get("default_branch")
            if branch and "get_ci_status" in names:
                result = await client.call_tool("get_ci_status", {"repo": repo, "ref": branch})
                data = result.structured_content or {}
                status = "FAIL" if result.is_error else "ok"
                failures += int(result.is_error)
                print(f"  {status:<5} {'get_ci_status':<20} {data.get('overall', '')} ({data.get('count', 0)} checks on {branch})")

    try:
        anyio.run(run)
    finally:
        logging.disable(logging.NOTSET)
    verified = guard.audit.verify()
    print(f"audit:  {verified.records} records, chain {'intact' if verified.ok else 'BROKEN'} ({policy.audit_path})")
    print("All read checks passed." if not failures else f"{failures} check(s) failed.")
    return 0 if not failures and verified.ok else 1


def cmd_demo(args: argparse.Namespace) -> int:
    from .demo import run_demo

    return run_demo(keep=args.keep)


# ------------------------------------------------------------------ entry point


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="guardrail-mcp",
        description="A policy-enforced MCP server that gives AI coding agents scoped, audited access to GitHub.",
    )
    parser.add_argument("--version", action="version", version=f"guardrail-mcp {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the MCP server (stdio by default)")
    _policy_arg(serve)
    serve.add_argument("--transport", choices=["stdio", "streamable-http"], default="stdio")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--agent-id", default=os.environ.get("GUARDRAIL_AGENT_ID", "agent"),
                       help="label for this agent in the audit log (default: $GUARDRAIL_AGENT_ID or 'agent')")
    serve.set_defaults(func=cmd_serve)

    check = sub.add_parser("check", help="validate a policy and print what the agent can and cannot do")
    _policy_arg(check)
    check.set_defaults(func=cmd_check)

    approvals = sub.add_parser("approvals", help="review and decide approval requests")
    approvals_sub = approvals.add_subparsers(dest="action", required=True)
    a_list = approvals_sub.add_parser("list", help="show pending requests")
    a_list.add_argument("--all", action="store_true", help="include decided and consumed requests")
    _policy_arg(a_list)
    for action in ("approve", "deny"):
        p = approvals_sub.add_parser(action, help=f"{action} a pending request")
        p.add_argument("id", help="approval id, for example apr_1a2b3c4d")
        p.add_argument("--by", help="who decided (default: your OS user name)")
        _policy_arg(p)
    approvals.set_defaults(func=cmd_approvals)

    audit = sub.add_parser("audit", help="inspect or verify the audit log")
    audit_sub = audit.add_subparsers(dest="action", required=True)
    tail = audit_sub.add_parser("tail", help="show the most recent records")
    tail.add_argument("-n", type=int, default=20)
    _policy_arg(tail)
    verify = audit_sub.add_parser("verify", help="check the hash chain for edits, deletions or reordering")
    _policy_arg(verify)
    audit.set_defaults(func=cmd_audit)

    doctor = sub.add_parser("doctor", help="read-only live check of your token, policy and a repository")
    _policy_arg(doctor)
    doctor.add_argument("--repo", help="owner/name to test (default: first exact repo in repos.allow)")
    doctor.set_defaults(func=cmd_doctor)

    demo = sub.add_parser("demo", help="offline walkthrough against an in-memory GitHub (no token needed)")
    demo.add_argument("--keep", action="store_true", help="keep the demo's audit log and print its path")
    demo.set_defaults(func=cmd_demo)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

