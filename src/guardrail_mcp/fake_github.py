"""An in-memory GitHub for the offline demo and the test suite.

It implements only the REST endpoints the tools use, returns GitHub-shaped
JSON, and records every request so tests can prove that a denied, dry-run or
replayed call never reached the API.
"""

from __future__ import annotations

import base64
import hashlib
import itertools
import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote

import httpx2

_counter = itertools.count(1)


def _sha(seed: str) -> str:
    return hashlib.sha1(f"{seed}:{next(_counter)}".encode()).hexdigest()


@dataclass
class FakeRepo:
    full_name: str
    default_branch: str = "main"
    private: bool = False
    description: str = ""
    branches: dict[str, str] = field(default_factory=dict)
    files: dict[str, dict[str, str]] = field(default_factory=dict)  # branch -> path -> content
    issues: dict[int, dict[str, Any]] = field(default_factory=dict)
    comments: dict[int, list[dict[str, Any]]] = field(default_factory=dict)
    pulls: dict[int, dict[str, Any]] = field(default_factory=dict)
    check_runs: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    reruns: list[int] = field(default_factory=list)
    next_number: int = 1

    @property
    def url(self) -> str:
        return f"https://github.com/{self.full_name}"


class FakeGitHub:
    def __init__(self) -> None:
        self.repos: dict[str, FakeRepo] = {}
        self.calls: list[tuple[str, str]] = []
        self._routes = [
            ("GET", r"/repos/(?P<repo>[^/]+/[^/]+)", self._get_repo),
            ("GET", r"/repos/(?P<repo>[^/]+/[^/]+)/issues", self._list_issues),
            ("POST", r"/repos/(?P<repo>[^/]+/[^/]+)/issues", self._create_issue),
            ("GET", r"/repos/(?P<repo>[^/]+/[^/]+)/issues/(?P<n>\d+)", self._get_issue),
            ("PATCH", r"/repos/(?P<repo>[^/]+/[^/]+)/issues/(?P<n>\d+)", self._update_issue),
            ("GET", r"/repos/(?P<repo>[^/]+/[^/]+)/issues/(?P<n>\d+)/comments", self._list_comments),
            ("POST", r"/repos/(?P<repo>[^/]+/[^/]+)/issues/(?P<n>\d+)/comments", self._create_comment),
            ("POST", r"/repos/(?P<repo>[^/]+/[^/]+)/issues/(?P<n>\d+)/labels", self._add_labels),
            ("GET", r"/repos/(?P<repo>[^/]+/[^/]+)/contents/(?P<path>.+)", self._get_contents),
            ("PUT", r"/repos/(?P<repo>[^/]+/[^/]+)/contents/(?P<path>.+)", self._put_contents),
            ("GET", r"/repos/(?P<repo>[^/]+/[^/]+)/git/ref/heads/(?P<branch>.+)", self._get_ref),
            ("POST", r"/repos/(?P<repo>[^/]+/[^/]+)/git/refs", self._create_ref),
            ("GET", r"/repos/(?P<repo>[^/]+/[^/]+)/pulls", self._list_pulls),
            ("POST", r"/repos/(?P<repo>[^/]+/[^/]+)/pulls", self._create_pull),
            ("GET", r"/repos/(?P<repo>[^/]+/[^/]+)/pulls/(?P<n>\d+)", self._get_pull),
            ("GET", r"/repos/(?P<repo>[^/]+/[^/]+)/pulls/(?P<n>\d+)/files", self._pull_files),
            ("PUT", r"/repos/(?P<repo>[^/]+/[^/]+)/pulls/(?P<n>\d+)/merge", self._merge_pull),
            ("GET", r"/repos/(?P<repo>[^/]+/[^/]+)/commits/(?P<ref>.+)/check-runs", self._check_runs),
            ("POST", r"/repos/(?P<repo>[^/]+/[^/]+)/actions/runs/(?P<run>\d+)/rerun-failed-jobs", self._rerun),
            ("GET", r"/search/code", self._search_code),
        ]

    # ---------------------------------------------------------------- plumbing

    @property
    def transport(self) -> httpx2.MockTransport:
        return httpx2.MockTransport(self.handle)

    @property
    def writes(self) -> list[tuple[str, str]]:
        return [c for c in self.calls if c[0] != "GET"]

    def add_repo(self, full_name: str, **kwargs: Any) -> FakeRepo:
        repo = FakeRepo(full_name=full_name, **kwargs)
        repo.branches.setdefault(repo.default_branch, _sha(full_name))
        repo.files.setdefault(repo.default_branch, {})
        self.repos[full_name.lower()] = repo
        return repo

    def add_issue(self, repo: FakeRepo, title: str, body: str = "", labels: list[str] | None = None) -> dict[str, Any]:
        number = repo.next_number
        repo.next_number += 1
        issue = {
            "number": number, "title": title, "body": body, "state": "open", "state_reason": None,
            "labels": [{"name": n} for n in (labels or [])], "assignees": [], "user": {"login": "maintainer"},
            "comments": 0, "updated_at": "2026-11-01T10:00:00Z", "html_url": f"{repo.url}/issues/{number}",
        }
        repo.issues[number] = issue
        repo.comments[number] = []
        return issue

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        method = request.method
        path = unquote(request.url.path)
        self.calls.append((method, path))
        body = json.loads(request.content) if request.content else {}
        for route_method, pattern, fn in self._routes:
            if route_method != method:
                continue
            match = re.fullmatch(pattern, path)
            if match:
                params = match.groupdict()
                repo = None
                if "repo" in params:
                    repo = self.repos.get(params.pop("repo").lower())
                    if repo is None:
                        return _error(404, "Not Found")
                return fn(repo, request, body, **params)
        return _error(404, "Not Found")

    # ---------------------------------------------------------------- repos

    def _get_repo(self, repo: FakeRepo, req, body) -> httpx2.Response:
        open_issues = sum(1 for i in repo.issues.values() if i["state"] == "open")
        return _ok({
            "full_name": repo.full_name, "default_branch": repo.default_branch, "private": repo.private,
            "description": repo.description, "open_issues_count": open_issues, "html_url": repo.url,
        })

    # ---------------------------------------------------------------- issues

    def _list_issues(self, repo: FakeRepo, req, body) -> httpx2.Response:
        state = req.url.params.get("state", "open")
        wanted = set(filter(None, req.url.params.get("labels", "").split(",")))
        items = [
            i for i in repo.issues.values()
            if (state == "all" or i["state"] == state) and wanted <= {lb["name"] for lb in i["labels"]}
        ]
        return _ok(items[: int(req.url.params.get("per_page", 30))])

    def _create_issue(self, repo: FakeRepo, req, body) -> httpx2.Response:
        if not body.get("title"):
            return _error(422, "Validation Failed", [{"field": "title", "code": "missing_field"}])
        return _ok(self.add_issue(repo, body["title"], body.get("body", ""), body.get("labels")), 201)

    def _get_issue(self, repo: FakeRepo, req, body, n: str) -> httpx2.Response:
        issue = repo.issues.get(int(n)) or repo.pulls.get(int(n))
        return _ok(issue) if issue else _error(404, "Not Found")

    def _update_issue(self, repo: FakeRepo, req, body, n: str) -> httpx2.Response:
        issue = repo.issues.get(int(n))
        if issue is None:
            return _error(404, "Not Found")
        issue.update({k: v for k, v in body.items() if k in ("state", "state_reason", "title", "body")})
        return _ok(issue)

    def _list_comments(self, repo: FakeRepo, req, body, n: str) -> httpx2.Response:
        comments = repo.comments.get(int(n), [])
        per_page = int(req.url.params.get("per_page", 30))
        page = int(req.url.params.get("page", 1))
        return _ok(comments[(page - 1) * per_page: page * per_page])

    def _create_comment(self, repo: FakeRepo, req, body, n: str) -> httpx2.Response:
        number = int(n)
        if number not in repo.issues and number not in repo.pulls:
            return _error(404, "Not Found")
        comment_id = next(_counter)
        comment = {
            "id": comment_id, "body": body.get("body", ""), "user": {"login": "agent-bot"},
            "created_at": "2026-11-02T08:00:00Z", "html_url": f"{repo.url}/issues/{number}#issuecomment-{comment_id}",
        }
        repo.comments.setdefault(number, []).append(comment)
        if number in repo.issues:
            repo.issues[number]["comments"] += 1
        return _ok(comment, 201)

    def _add_labels(self, repo: FakeRepo, req, body, n: str) -> httpx2.Response:
        issue = repo.issues.get(int(n))
        if issue is None:
            return _error(404, "Not Found")
        names = [lb["name"] for lb in issue["labels"]]
        for label in body.get("labels", []):
            if label not in names:
                issue["labels"].append({"name": label})
        return _ok(issue["labels"])

    # ---------------------------------------------------------------- contents and refs

    def _get_contents(self, repo: FakeRepo, req, body, path: str) -> httpx2.Response:
        branch = req.url.params.get("ref") or repo.default_branch
        files = repo.files.get(branch)
        if files is None:
            return _error(404, "No commit found for the ref")
        if path in files:
            raw = files[path].encode("utf-8")
            return _ok({
                "type": "file", "path": path, "name": path.rsplit("/", 1)[-1], "size": len(raw),
                "sha": hashlib.sha1(raw).hexdigest(), "encoding": "base64",
                "content": base64.b64encode(raw).decode("ascii"),
            })
        prefix = path.rstrip("/") + "/"
        children = sorted({p[len(prefix):].split("/")[0] for p in files if p.startswith(prefix)})
        if children:
            return _ok([
                {"name": c, "path": prefix + c, "type": "file" if prefix + c in files else "dir", "size": 0}
                for c in children
            ])
        return _error(404, "Not Found")

    def _put_contents(self, repo: FakeRepo, req, body, path: str) -> httpx2.Response:
        branch = body.get("branch") or repo.default_branch
        if branch not in repo.branches:
            return _error(404, "Branch not found")
        files = repo.files[branch]
        if path in files:
            current = hashlib.sha1(files[path].encode("utf-8")).hexdigest()
            if body.get("sha") != current:
                return _error(409, f"{path} does not match {body.get('sha')}")
        files[path] = base64.b64decode(body["content"]).decode("utf-8")
        commit = _sha(path)
        repo.branches[branch] = commit
        return _ok({"content": {"path": path, "html_url": f"{repo.url}/blob/{branch}/{path}"}, "commit": {"sha": commit}}, 201)

    def _get_ref(self, repo: FakeRepo, req, body, branch: str) -> httpx2.Response:
        sha = repo.branches.get(branch)
        if sha is None:
            return _error(404, "Not Found")
        return _ok({"ref": f"refs/heads/{branch}", "object": {"sha": sha, "type": "commit"}})

    def _create_ref(self, repo: FakeRepo, req, body) -> httpx2.Response:
        name = body["ref"].removeprefix("refs/heads/")
        if name in repo.branches:
            return _error(422, "Reference already exists")
        source = next((b for b, s in repo.branches.items() if s == body["sha"]), repo.default_branch)
        repo.branches[name] = body["sha"]
        repo.files[name] = dict(repo.files.get(source, {}))
        return _ok({"ref": body["ref"], "object": {"sha": body["sha"]}}, 201)

    # ---------------------------------------------------------------- pull requests

    def _list_pulls(self, repo: FakeRepo, req, body) -> httpx2.Response:
        state = req.url.params.get("state", "open")
        return _ok([p for p in repo.pulls.values() if state == "all" or p["state"] == state])

    def _create_pull(self, repo: FakeRepo, req, body) -> httpx2.Response:
        head, base = body.get("head"), body.get("base")
        if head not in repo.branches or base not in repo.branches:
            return _error(422, "Validation Failed", [{"message": "head or base branch does not exist"}])
        if any(p["head"]["ref"] == head and p["state"] == "open" for p in repo.pulls.values()):
            return _error(422, "Validation Failed", [{"message": f"A pull request already exists for {head}."}])
        number = repo.next_number
        repo.next_number += 1
        pr = {
            "number": number, "title": body["title"], "body": body.get("body", ""), "state": "open",
            "draft": bool(body.get("draft")), "merged": False, "mergeable": True, "user": {"login": "agent-bot"},
            "head": {"ref": head, "sha": repo.branches[head]}, "base": {"ref": base, "sha": repo.branches[base]},
            "html_url": f"{repo.url}/pull/{number}", "pull_request": {},
        }
        repo.pulls[number] = pr
        return _ok(pr, 201)

    def _get_pull(self, repo: FakeRepo, req, body, n: str) -> httpx2.Response:
        pr = repo.pulls.get(int(n))
        return _ok(pr) if pr else _error(404, "Not Found")

    def _pull_files(self, repo: FakeRepo, req, body, n: str) -> httpx2.Response:
        pr = repo.pulls.get(int(n))
        if pr is None:
            return _error(404, "Not Found")
        head = repo.files.get(pr["head"]["ref"], {})
        base = repo.files.get(pr["base"]["ref"], {})
        changed = [
            {"filename": p, "status": "added" if p not in base else "modified",
             "additions": c.count("\n") + 1, "deletions": 0 if p not in base else base[p].count("\n") + 1}
            for p, c in head.items() if base.get(p) != c
        ]
        return _ok(changed)

    def _merge_pull(self, repo: FakeRepo, req, body, n: str) -> httpx2.Response:
        pr = repo.pulls.get(int(n))
        if pr is None:
            return _error(404, "Not Found")
        if pr["draft"]:
            return _error(405, "Pull Request is still a draft")
        pr.update({"merged": True, "state": "closed"})
        return _ok({"merged": True, "sha": _sha("merge"), "message": "Pull Request successfully merged"})

    # ---------------------------------------------------------------- CI

    def _check_runs(self, repo: FakeRepo, req, body, ref: str) -> httpx2.Response:
        runs = repo.check_runs.get(ref, [])
        return _ok({"total_count": len(runs), "check_runs": runs})

    def _rerun(self, repo: FakeRepo, req, body, run: str) -> httpx2.Response:
        repo.reruns.append(int(run))
        return httpx2.Response(201)

    # ---------------------------------------------------------------- search

    def _search_code(self, repo: FakeRepo | None, req, body) -> httpx2.Response:
        q = req.url.params.get("q", "")
        match = re.search(r"repo:(\S+)", q)
        target = self.repos.get(match.group(1).lower()) if match else None
        terms = re.sub(r"repo:\S+", "", q).strip()
        if target is None:
            return _error(422, "Validation Failed")
        files = target.files.get(target.default_branch, {})
        items = [{"path": p, "html_url": f"{target.url}/blob/{target.default_branch}/{p}"} for p, c in files.items() if terms in c]
        return _ok({"total_count": len(items), "items": items})


def _ok(data: Any, status: int = 200) -> httpx2.Response:
    return httpx2.Response(status, json=data)


def _error(status: int, message: str, errors: list[dict[str, Any]] | None = None) -> httpx2.Response:
    payload: dict[str, Any] = {"message": message}
    if errors:
        payload["errors"] = errors
    return httpx2.Response(status, json=payload)


def demo_github() -> FakeGitHub:
    """A small, realistic sandbox: one repo the agent may use and one it may not."""
    gh = FakeGitHub()
    web = gh.add_repo("acme/web-app", description="Storefront web app")
    # Assembled at runtime so this file never contains a credential-shaped literal.
    leaked_key = "AKIA" + "IOSFODNN7" + "EXAMPLE"
    web.files["main"].update({
        "README.md": "# web-app\n\nStorefront for Acme.\n",
        "src/checkout.py": "def submit_order(cart):\n    # TODO: debounce double clicks\n    return api.post('/orders', cart)\n",
        "config/settings.py": f"DEBUG = False\nAWS_ACCESS_KEY_ID = '{leaked_key}'\n",
        ".env": "STRIPE_SECRET=do-not-read\n",
    })
    gh.add_issue(web, "Checkout button double-submits on slow networks", "Customers get charged twice when they click Pay twice.", ["bug", "checkout"])
    gh.add_issue(web, "Flaky test: test_payment_retry", "Fails about 1 in 10 runs on CI.", ["flaky-test"])
    gh.add_issue(web, "Update README badges", "", ["docs"])
    web.check_runs["main"] = [
        {"name": "unit-tests", "status": "completed", "conclusion": "failure",
         "details_url": "https://github.com/acme/web-app/actions/runs/9001/job/1"},
        {"name": "lint", "status": "completed", "conclusion": "success",
         "details_url": "https://github.com/acme/web-app/actions/runs/9001/job/2"},
    ]
    billing = gh.add_repo("acme/billing", private=True, description="Payments service")
    gh.add_issue(billing, "Rotate payment provider keys")
    return gh
