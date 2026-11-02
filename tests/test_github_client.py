import time

import httpx2
import pytest

from guardrail_mcp.github import GitHubClient, GitHubError

pytestmark = pytest.mark.anyio


class Recorder:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests: list[httpx2.Request] = []
        self.sleeps: list[float] = []

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        nxt = self.responses.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)

    def client(self, **kwargs) -> GitHubClient:
        return GitHubClient("t", transport=httpx2.MockTransport(self.handler), sleep=self.sleep, **kwargs)


async def test_get_retries_server_errors() -> None:
    rec = Recorder([httpx2.Response(502), httpx2.Response(503), httpx2.Response(200, json={"ok": True})])
    assert await rec.client().get("/repos/a/b") == {"ok": True}
    assert len(rec.requests) == 3 and len(rec.sleeps) == 2


async def test_post_is_not_retried_on_server_error() -> None:
    rec = Recorder([httpx2.Response(502), httpx2.Response(201, json={})])
    with pytest.raises(GitHubError) as exc:
        await rec.client().request("POST", "/repos/a/b/issues", json={"title": "x"})
    assert exc.value.status == 502
    assert "may or may not have been applied" in str(exc.value)
    assert len(rec.requests) == 1


async def test_post_is_retried_when_the_connection_never_opened() -> None:
    rec = Recorder([httpx2.ConnectError("refused"), httpx2.Response(201, json={"number": 7})])
    assert await rec.client().request("POST", "/repos/a/b/issues", json={}) == {"number": 7}
    assert len(rec.requests) == 2


async def test_secondary_rate_limit_honors_retry_after() -> None:
    limited = httpx2.Response(403, headers={"retry-after": "2"}, json={"message": "secondary rate limit"})
    rec = Recorder([limited, httpx2.Response(201, json={"id": 1})])
    assert await rec.client().request("POST", "/x", json={}) == {"id": 1}
    assert rec.sleeps == [2.0]


async def test_long_rate_limit_fails_fast_with_reset_time() -> None:
    reset = str(int(time.time()) + 3600)
    limited = httpx2.Response(403, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": reset}, json={})
    rec = Recorder([limited])
    with pytest.raises(GitHubError) as exc:
        await rec.client(max_wait=30).get("/x")
    assert exc.value.status == 429 and "retry in about" in str(exc.value)
    assert rec.sleeps == []


async def test_plain_403_is_a_permission_error_not_a_rate_limit() -> None:
    rec = Recorder([httpx2.Response(403, json={"message": "Resource not accessible by integration"})])
    with pytest.raises(GitHubError) as exc:
        await rec.client().request("POST", "/x", json={})
    assert exc.value.status == 403 and "lacks permission" in str(exc.value)
    assert len(rec.requests) == 1


async def test_validation_errors_are_readable() -> None:
    body = {"message": "Validation Failed", "errors": [{"message": "A pull request already exists for agent/x."}]}
    rec = Recorder([httpx2.Response(422, json=body)])
    with pytest.raises(GitHubError) as exc:
        await rec.client().request("POST", "/pulls", json={})
    assert "A pull request already exists" in str(exc.value)


async def test_no_content_returns_none() -> None:
    rec = Recorder([httpx2.Response(204)])
    assert await rec.client().request("POST", "/rerun") is None


async def test_auth_header_and_api_version() -> None:
    rec = Recorder([httpx2.Response(200, json={})])
    await rec.client().get("/x")
    headers = rec.requests[0].headers
    assert headers["authorization"] == "Bearer t"
    assert headers["x-github-api-version"] == "2022-11-28"
