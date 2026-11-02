"""The MCP tools. Each one builds its GitHub request, then hands it to the guard.

Tool docstrings are what the agent reads, so they say what the tool does and
what the policy will refuse, in plain words.
"""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Callable
from typing import Annotated, Any, Literal
from urllib.parse import quote

from mcp.server.mcpserver import Context
from pydantic import Field

from .catalog import CATALOG, ToolSpec
from .github import GitHubClient, GitHubError
from .guard import Guard

Repo = Annotated[
    str,
    Field(description="Repository as owner/name, for example acme/api", pattern=r"^[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+$"),
]
Number = Annotated[int, Field(ge=1, description="Issue or pull request number")]
DryRun = Annotated[bool, Field(description="Preview the write without performing it")]
Limit = Annotated[int, Field(ge=1, le=100, description="Maximum items to return")]

_RUN_ID = re.compile(r"/actions/runs/(\d+)")


def _path(path: str) -> str:
    return quote(path.strip().lstrip("/"), safe="/")


def _ref(ref: str) -> str:
    return quote(ref, safe="")


def _preview(method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"method": method, "endpoint": path, **({"body": body} if body else {})}


def _user(obj: dict[str, Any] | None) -> str | None:
    return (obj or {}).get("login")


def _clip(text: str | None, limit: int) -> str:
    text = text or ""
    return text if len(text) <= limit else text[:limit] + f"\n... [truncated, {len(text)} chars total]"


def build_tools(guard: Guard, gh: GitHubClient) -> list[tuple[Callable[..., Any], ToolSpec]]:
    policy = guard.policy
    text_cap = policy.limits.max_text_chars
    tools: list[Callable[..., Any]] = []

    def tool(fn: Callable[..., Any]) -> Callable[..., Any]:
        tools.append(fn)
        return fn

    # ================================================================ meta

    @tool
    async def describe_permissions(ctx: Context = None) -> dict[str, Any]:
        """Show exactly what you may and may not do in this session: allowed repositories and tools,
        tools that need human approval, writable branches, protected paths and remaining write budget.
        Call this first, and whenever an action is denied."""

        async def run() -> dict[str, Any]:
            remaining = max(0, policy.limits.max_writes_per_session - guard.writes_used)
            return {**policy.describe(), "session": {"id": guard.session_id, "writes_used": guard.writes_used, "writes_remaining": remaining}}

        return await guard.run("describe_permissions", {}, run, ctx=ctx)

    # ================================================================ reads

    @tool
    async def get_repo(repo: Repo, ctx: Context = None) -> dict[str, Any]:
        """Get repository metadata: default branch, visibility, open issue count and description."""

        async def run() -> dict[str, Any]:
            r = await gh.get(f"/repos/{repo}")
            return {
                "full_name": r["full_name"],
                "default_branch": r["default_branch"],
                "private": r["private"],
                "description": r.get("description"),
                "open_issues_count": r.get("open_issues_count"),
                "html_url": r["html_url"],
            }

        return await guard.run("get_repo", {"repo": repo}, run, ctx=ctx)

    @tool
    async def list_issues(
        repo: Repo,
        state: Literal["open", "closed", "all"] = "open",
        labels: Annotated[list[str] | None, Field(description="Only issues with all of these labels")] = None,
        limit: Limit = 30,
        ctx: Context = None,
    ) -> dict[str, Any]:
        """List issues (pull requests excluded), most recently updated first."""

        async def run() -> dict[str, Any]:
            data = await gh.get(
                f"/repos/{repo}/issues",
                state=state,
                labels=",".join(labels) if labels else None,
                per_page=limit,
                sort="updated",
            )
            items = [
                {
                    "number": i["number"],
                    "title": i["title"],
                    "state": i["state"],
                    "labels": [lb["name"] for lb in i.get("labels", [])],
                    "assignees": [a["login"] for a in i.get("assignees", [])],
                    "updated_at": i.get("updated_at"),
                    "html_url": i["html_url"],
                }
                for i in data
                if "pull_request" not in i
            ]
            return {"count": len(items), "items": items}

        return await guard.run("list_issues", {"repo": repo, "state": state, "labels": labels, "limit": limit}, run, ctx=ctx)

    @tool
    async def get_issue(
        repo: Repo,
        number: Number,
        comments_limit: Annotated[int, Field(ge=0, le=100)] = 20,
        ctx: Context = None,
    ) -> dict[str, Any]:
        """Get one issue with its body and the most recent comments."""

        async def run() -> dict[str, Any]:
            i = await gh.get(f"/repos/{repo}/issues/{number}")
            comments: list[dict[str, Any]] = []
            if comments_limit and i.get("comments"):
                total = int(i["comments"])
                last_page = max(1, -(-total // comments_limit))
                raw = await gh.get(f"/repos/{repo}/issues/{number}/comments", per_page=comments_limit, page=last_page)
                comments = [
                    {"id": c["id"], "author": _user(c.get("user")), "created_at": c.get("created_at"), "body": _clip(c.get("body"), text_cap)}
                    for c in raw
                ]
            return {
                "number": i["number"],
                "title": i["title"],
                "state": i["state"],
                "author": _user(i.get("user")),
                "labels": [lb["name"] for lb in i.get("labels", [])],
                "body": _clip(i.get("body"), text_cap),
                "is_pull_request": "pull_request" in i,
                "comments_total": i.get("comments", 0),
                "comments": comments,
                "html_url": i["html_url"],
            }

        return await guard.run("get_issue", {"repo": repo, "number": number, "comments_limit": comments_limit}, run, ctx=ctx)

    @tool
    async def search_code(
        repo: Repo,
        query: Annotated[str, Field(min_length=1, max_length=256, description="GitHub code search terms")],
        limit: Limit = 20,
        ctx: Context = None,
    ) -> dict[str, Any]:
        """Search code in one repository. Returns file paths; use get_file to read a match.
        Requires an authenticated token."""

        async def run() -> dict[str, Any]:
            data = await gh.get("/search/code", q=f"{query} repo:{repo}", per_page=limit)
            items = [{"path": it["path"], "html_url": it["html_url"]} for it in data.get("items", [])]
            return {"count": len(items), "total_matches": data.get("total_count", len(items)), "items": items}

        return await guard.run("search_code", {"repo": repo, "query": query, "limit": limit}, run, ctx=ctx)

    @tool
    async def get_file(
        repo: Repo,
        path: Annotated[str, Field(description="File or directory path, for example src/app.py")],
        ref: Annotated[str | None, Field(description="Branch, tag or commit SHA; default branch if omitted")] = None,
        ctx: Context = None,
    ) -> dict[str, Any]:
        """Read a text file, or list a directory. Secret files (.env, keys) are blocked by policy and any
        credentials inside returned content are redacted."""

        async def run() -> dict[str, Any]:
            data = await gh.get(f"/repos/{repo}/contents/{_path(path)}", ref=ref)
            if isinstance(data, list):
                entries = [{"name": e["name"], "path": e["path"], "type": e["type"], "size": e.get("size")} for e in data]
                return {"path": path, "type": "dir", "count": len(entries), "items": entries}
            size = int(data.get("size") or 0)
            if size > policy.limits.max_file_bytes:
                return {"path": data["path"], "type": "file", "size": size, "sha": data["sha"], "content": None,
                        "note": f"file is larger than {policy.limits.max_file_bytes} bytes and was not returned"}
            raw = base64.b64decode(data.get("content") or "")
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                return {"path": data["path"], "type": "file", "size": size, "sha": data["sha"], "content": None,
                        "note": "binary file, content not returned"}
            return {"path": data["path"], "type": "file", "size": size, "sha": data["sha"], "content": text}

        return await guard.run("get_file", {"repo": repo, "path": path, "ref": ref}, run, ctx=ctx)

    @tool
    async def list_pull_requests(
        repo: Repo,
        state: Literal["open", "closed", "all"] = "open",
        limit: Limit = 30,
        ctx: Context = None,
    ) -> dict[str, Any]:
        """List pull requests with their head and base branches."""

        async def run() -> dict[str, Any]:
            data = await gh.get(f"/repos/{repo}/pulls", state=state, per_page=limit)
            items = [
                {
                    "number": pr["number"],
                    "title": pr["title"],
                    "state": pr["state"],
                    "draft": pr.get("draft", False),
                    "author": _user(pr.get("user")),
                    "head": pr["head"]["ref"],
                    "base": pr["base"]["ref"],
                    "html_url": pr["html_url"],
                }
                for pr in data
            ]
            return {"count": len(items), "items": items}

        return await guard.run("list_pull_requests", {"repo": repo, "state": state, "limit": limit}, run, ctx=ctx)

    @tool
    async def get_pull_request(repo: Repo, number: Number, ctx: Context = None) -> dict[str, Any]:
        """Get a pull request: status, mergeability, branches and the list of changed files."""

        async def run() -> dict[str, Any]:
            pr = await gh.get(f"/repos/{repo}/pulls/{number}")
            files = await gh.get(f"/repos/{repo}/pulls/{number}/files", per_page=100)
            return {
                "number": pr["number"],
                "title": pr["title"],
                "state": pr["state"],
                "draft": pr.get("draft", False),
                "merged": pr.get("merged", False),
                "mergeable": pr.get("mergeable"),
                "author": _user(pr.get("user")),
                "head": pr["head"]["ref"],
                "base": pr["base"]["ref"],
                "head_sha": pr["head"]["sha"],
                "body": _clip(pr.get("body"), text_cap),
                "changed_files": [
                    {"path": f["filename"], "status": f["status"], "additions": f["additions"], "deletions": f["deletions"]}
                    for f in files
                ],
                "html_url": pr["html_url"],
            }

        return await guard.run("get_pull_request", {"repo": repo, "number": number}, run, ctx=ctx)

    @tool
    async def get_ci_status(
        repo: Repo,
        ref: Annotated[str, Field(description="Branch name or commit SHA")],
        ctx: Context = None,
    ) -> dict[str, Any]:
        """Summarize CI checks for a branch or commit: overall result, failing checks and the
        GitHub Actions run ids you can pass to rerun_failed_jobs."""

        async def run() -> dict[str, Any]:
            data = await gh.get(f"/repos/{repo}/commits/{_ref(ref)}/check-runs", per_page=100)
            checks = []
            for c in data.get("check_runs", []):
                match = _RUN_ID.search(c.get("details_url") or "")
                checks.append({
                    "name": c["name"],
                    "status": c["status"],
                    "conclusion": c.get("conclusion"),
                    "run_id": int(match.group(1)) if match else None,
                    "details_url": c.get("details_url"),
                })
            failing = [c for c in checks if c["conclusion"] in ("failure", "timed_out", "cancelled", "action_required")]
            pending = [c for c in checks if c["status"] != "completed"]
            overall = "none" if not checks else "failure" if failing else "pending" if pending else "success"
            return {"ref": ref, "overall": overall, "count": len(checks), "failing": failing, "items": checks}

        return await guard.run("get_ci_status", {"repo": repo, "ref": ref}, run, ctx=ctx)

    # ================================================================ writes

    @tool
    async def create_issue(
        repo: Repo,
        title: Annotated[str, Field(min_length=1, max_length=256)],
        body: str = "",
        labels: list[str] | None = None,
        dry_run: DryRun = False,
        ctx: Context = None,
    ) -> dict[str, Any]:
        """Create an issue. Text containing credentials is refused."""
        payload = {"title": title, "body": body, "labels": labels or []}
        endpoint = f"/repos/{repo}/issues"

        async def run() -> dict[str, Any]:
            r = await gh.request("POST", endpoint, json=payload)
            return {"number": r["number"], "html_url": r["html_url"]}

        return await guard.run(
            "create_issue", {"repo": repo, **payload}, run, ctx=ctx, dry_run=dry_run, preview=_preview("POST", endpoint, payload)
        )

    @tool
    async def comment_on_issue(
        repo: Repo,
        number: Number,
        body: Annotated[str, Field(min_length=1)],
        dry_run: DryRun = False,
        ctx: Context = None,
    ) -> dict[str, Any]:
        """Add a comment to an issue or pull request. Text containing credentials is refused."""
        endpoint = f"/repos/{repo}/issues/{number}/comments"

        async def run() -> dict[str, Any]:
            r = await gh.request("POST", endpoint, json={"body": body})
            return {"number": number, "comment_id": r["id"], "html_url": r["html_url"]}

        return await guard.run(
            "comment_on_issue", {"repo": repo, "number": number, "body": body}, run,
            ctx=ctx, dry_run=dry_run, preview=_preview("POST", endpoint, {"body": body}),
        )

    @tool
    async def add_labels(
        repo: Repo,
        number: Number,
        labels: Annotated[list[str], Field(min_length=1)],
        dry_run: DryRun = False,
        ctx: Context = None,
    ) -> dict[str, Any]:
        """Add labels to an issue or pull request."""
        endpoint = f"/repos/{repo}/issues/{number}/labels"

        async def run() -> dict[str, Any]:
            r = await gh.request("POST", endpoint, json={"labels": labels})
            return {"number": number, "labels": [lb["name"] for lb in r]}

        return await guard.run(
            "add_labels", {"repo": repo, "number": number, "labels": labels}, run,
            ctx=ctx, dry_run=dry_run, preview=_preview("POST", endpoint, {"labels": labels}),
        )

    @tool
    async def close_issue(
        repo: Repo,
        number: Number,
        reason: Literal["completed", "not_planned"] = "completed",
        comment: Annotated[str | None, Field(description="Optional closing comment")] = None,
        dry_run: DryRun = False,
        ctx: Context = None,
    ) -> dict[str, Any]:
        """Close an issue, optionally with a comment explaining why."""
        endpoint = f"/repos/{repo}/issues/{number}"
        payload = {"state": "closed", "state_reason": reason}

        async def run() -> dict[str, Any]:
            if comment:
                await gh.request("POST", f"{endpoint}/comments", json={"body": comment})
            r = await gh.request("PATCH", endpoint, json=payload)
            return {"number": r["number"], "state": r["state"], "html_url": r["html_url"]}

        return await guard.run(
            "close_issue", {"repo": repo, "number": number, "reason": reason, "comment": comment}, run,
            ctx=ctx, dry_run=dry_run, preview=_preview("PATCH", endpoint, payload),
        )

    @tool
    async def create_branch(
        repo: Repo,
        branch: Annotated[str, Field(description="New branch name; must start with the policy's agent prefix")],
        from_ref: Annotated[str | None, Field(description="Branch to start from; default branch if omitted")] = None,
        dry_run: DryRun = False,
        ctx: Context = None,
    ) -> dict[str, Any]:
        """Create a branch for your work. Only branches with the agent prefix (see describe_permissions) are allowed."""
        endpoint = f"/repos/{repo}/git/refs"

        async def run() -> dict[str, Any]:
            source = from_ref or (await gh.get(f"/repos/{repo}"))["default_branch"]
            head = await gh.get(f"/repos/{repo}/git/ref/heads/{_ref(source)}")
            sha = head["object"]["sha"]
            await gh.request("POST", endpoint, json={"ref": f"refs/heads/{branch}", "sha": sha})
            return {"branch": branch, "from": source, "sha": sha}

        return await guard.run(
            "create_branch", {"repo": repo, "branch": branch, "from_ref": from_ref}, run,
            ctx=ctx, dry_run=dry_run, preview=_preview("POST", endpoint, {"ref": f"refs/heads/{branch}", "from": from_ref or "<default branch>"}),
        )

    @tool
    async def commit_file(
        repo: Repo,
        branch: Annotated[str, Field(description="Agent branch to commit to (create it first with create_branch)")],
        path: Annotated[str, Field(description="File path to create or update")],
        content: Annotated[str, Field(description="Full new UTF-8 content of the file")],
        message: Annotated[str, Field(min_length=1, description="Commit message")],
        dry_run: DryRun = False,
        ctx: Context = None,
    ) -> dict[str, Any]:
        """Create or update one file on an agent branch. Protected branches, CI workflow files and
        secret files are refused, as is content containing credentials."""
        clean_path = path.strip().lstrip("/")
        endpoint = f"/repos/{repo}/contents/{_path(clean_path)}"
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()

        async def run() -> dict[str, Any]:
            existing_sha = None
            try:
                current = await gh.get(endpoint, ref=branch)
                if isinstance(current, dict):
                    existing_sha = current.get("sha")
            except GitHubError as exc:
                if exc.status != 404:
                    raise
            body: dict[str, Any] = {
                "message": message,
                "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
                "branch": branch,
            }
            if existing_sha:
                body["sha"] = existing_sha
            r = await gh.request("PUT", endpoint, json=body)
            return {
                "path": clean_path,
                "branch": branch,
                "commit_sha": r["commit"]["sha"],
                "created": existing_sha is None,
                "html_url": (r.get("content") or {}).get("html_url"),
            }

        return await guard.run(
            "commit_file", {"repo": repo, "branch": branch, "path": clean_path, "content": content, "message": message}, run,
            ctx=ctx, dry_run=dry_run,
            preview=_preview("PUT", endpoint, {"branch": branch, "message": message, "content_bytes": len(content.encode("utf-8")), "content_sha256": digest}),
        )

    @tool
    async def open_pull_request(
        repo: Repo,
        head: Annotated[str, Field(description="Your agent branch with the changes")],
        title: Annotated[str, Field(min_length=1, max_length=256)],
        base: Annotated[str, Field(description="Branch to merge into, for example main")] = "main",
        body: str = "",
        draft: bool = True,
        dry_run: DryRun = False,
        ctx: Context = None,
    ) -> dict[str, Any]:
        """Open a pull request from an agent branch. The policy may force it to draft so a human reviews it."""
        endpoint = f"/repos/{repo}/pulls"
        forced = policy.pull_requests.force_draft and not draft
        payload = {"title": title, "head": head, "base": base, "body": body, "draft": draft or policy.pull_requests.force_draft}

        async def run() -> dict[str, Any]:
            r = await gh.request("POST", endpoint, json=payload)
            result = {"number": r["number"], "html_url": r["html_url"], "head": head, "base": base, "draft": r.get("draft", payload["draft"])}
            if forced:
                result["policy_note"] = "opened as draft because the policy requires human review"
            return result

        return await guard.run(
            "open_pull_request", {"repo": repo, "head": head, "base": base, "title": title, "body": body, "draft": draft}, run,
            ctx=ctx, dry_run=dry_run, preview=_preview("POST", endpoint, payload),
        )

    @tool
    async def merge_pull_request(
        repo: Repo,
        number: Number,
        method: Literal["squash", "merge", "rebase"] = "squash",
        dry_run: DryRun = False,
        ctx: Context = None,
    ) -> dict[str, Any]:
        """Merge a pull request. Usually disabled or gated behind human approval by policy."""
        endpoint = f"/repos/{repo}/pulls/{number}/merge"

        async def run() -> dict[str, Any]:
            r = await gh.request("PUT", endpoint, json={"merge_method": method})
            return {"number": number, "merged": r.get("merged", False), "sha": r.get("sha")}

        return await guard.run(
            "merge_pull_request", {"repo": repo, "number": number, "method": method}, run,
            ctx=ctx, dry_run=dry_run, preview=_preview("PUT", endpoint, {"merge_method": method}),
        )

    @tool
    async def rerun_failed_jobs(
        repo: Repo,
        run_id: Annotated[int, Field(ge=1, description="GitHub Actions run id from get_ci_status")],
        dry_run: DryRun = False,
        ctx: Context = None,
    ) -> dict[str, Any]:
        """Re-run only the failed jobs of a GitHub Actions workflow run, for example after fixing a flaky test."""
        endpoint = f"/repos/{repo}/actions/runs/{run_id}/rerun-failed-jobs"

        async def run() -> dict[str, Any]:
            await gh.request("POST", endpoint)
            return {"run_id": run_id, "rerun": "requested"}

        return await guard.run(
            "rerun_failed_jobs", {"repo": repo, "run_id": run_id}, run,
            ctx=ctx, dry_run=dry_run, preview=_preview("POST", endpoint),
        )

    missing = set(CATALOG) - {fn.__name__ for fn in tools}
    assert not missing, f"catalog tools without an implementation: {missing}"
    return [(fn, CATALOG[fn.__name__]) for fn in tools]
