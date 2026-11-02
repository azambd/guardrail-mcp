"""A small GitHub REST client built for agents: honest errors and careful retries.

Retry rules, chosen so a retry can never duplicate a write:

* Rate limits (429, or 403 with ``retry-after`` / ``x-ratelimit-remaining: 0``)
  are retried for every method, because GitHub rejected the request outright.
  Waits longer than ``max_wait`` are not slept through; the agent gets a clear
  error with the reset time instead of a hung call.
* Connection failures before the request was sent are retried for every method.
* 5xx responses and read timeouts are retried for GET only. For a POST the
  write may already have landed, so it is reported instead of repeated.
"""

from __future__ import annotations

import random
import time
from collections.abc import Awaitable, Callable
from typing import Any

import anyio
import httpx2

API_URL = "https://api.github.com"
API_VERSION = "2022-11-28"

_HINTS = {
    401: "the GitHub token is missing, expired or invalid",
    403: "the token lacks permission for this action",
    404: "not found; check the repository, number, branch or path (private repos also return 404 without access)",
    409: "conflict; the branch or file changed underneath the request",
    422: "GitHub rejected the input",
}


class GitHubError(Exception):
    def __init__(self, status: int, message: str, *, method: str = "", path: str = "") -> None:
        self.status = status
        self.message = message
        self.method = method
        self.path = path
        super().__init__(str(self))

    def __str__(self) -> str:
        hint = _HINTS.get(self.status)
        where = f" ({self.method} {self.path})" if self.method else ""
        return f"GitHub {self.status}{where}: {self.message}" + (f". Hint: {hint}" if hint else "")


class GitHubClient:
    def __init__(
        self,
        token: str | None,
        *,
        base_url: str = API_URL,
        transport: httpx2.AsyncBaseTransport | None = None,
        max_retries: int = 3,
        max_wait: float = 30.0,
        timeout: float = 20.0,
        sleep: Callable[[float], Awaitable[None]] = anyio.sleep,
    ) -> None:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "guardrail-mcp",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self.authenticated = bool(token)
        self._http = httpx2.AsyncClient(base_url=base_url, headers=headers, timeout=timeout, transport=transport)
        self._max_retries = max_retries
        self._max_wait = max_wait
        self._sleep = sleep

    async def aclose(self) -> None:
        await self._http.aclose()

    async def get(self, path: str, **params: Any) -> Any:
        return await self.request("GET", path, params={k: v for k, v in params.items() if v is not None})

    async def request(
        self, method: str, path: str, *, params: dict[str, Any] | None = None, json: Any = None
    ) -> Any:
        method = method.upper()
        attempt = 0
        while True:
            try:
                response = await self._http.request(method, path, params=params, json=json)
            except (httpx2.ConnectError, httpx2.ConnectTimeout, httpx2.PoolTimeout) as exc:
                if attempt < self._max_retries:
                    attempt += 1
                    await self._sleep(self._backoff(attempt))
                    continue
                raise GitHubError(0, f"could not connect to GitHub: {exc}", method=method, path=path) from exc
            except httpx2.TransportError as exc:
                if method == "GET" and attempt < self._max_retries:
                    attempt += 1
                    await self._sleep(self._backoff(attempt))
                    continue
                note = "" if method == "GET" else "; the write may or may not have been applied, check before retrying"
                raise GitHubError(0, f"network error: {type(exc).__name__}{note}", method=method, path=path) from exc

            wait = self._rate_limit_wait(response)
            if wait is not None:
                if attempt < self._max_retries and wait <= self._max_wait:
                    attempt += 1
                    await self._sleep(wait)
                    continue
                raise GitHubError(
                    429,
                    f"rate limited by GitHub; retry in about {int(wait)}s",
                    method=method,
                    path=path,
                )

            if response.status_code >= 500:
                if method == "GET" and attempt < self._max_retries:
                    attempt += 1
                    await self._sleep(self._backoff(attempt))
                    continue
                note = "" if method == "GET" else "; the write may or may not have been applied, check before retrying"
                raise GitHubError(response.status_code, f"GitHub server error{note}", method=method, path=path)

            if response.status_code >= 400:
                raise GitHubError(response.status_code, _error_message(response), method=method, path=path)

            if response.status_code == 204 or not response.content:
                return None
            return response.json()

    def _rate_limit_wait(self, response: httpx2.Response) -> float | None:
        if response.status_code not in (403, 429):
            return None
        retry_after = response.headers.get("retry-after")
        if retry_after is not None:
            try:
                return max(1.0, float(retry_after))
            except ValueError:
                return 60.0
        if response.headers.get("x-ratelimit-remaining") == "0":
            reset = response.headers.get("x-ratelimit-reset")
            try:
                return max(1.0, float(reset) - time.time()) if reset else 60.0
            except ValueError:
                return 60.0
        if response.status_code == 429:
            return 60.0
        return None  # a plain 403 is a permission problem, not a rate limit

    def _backoff(self, attempt: int) -> float:
        return min(self._max_wait, 0.5 * (2 ** (attempt - 1))) + random.uniform(0, 0.25)


def _error_message(response: httpx2.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return response.reason_phrase or "error"
    message = str(body.get("message", "error")) if isinstance(body, dict) else "error"
    details = []
    for err in (body.get("errors") or []) if isinstance(body, dict) else []:
        if isinstance(err, dict):
            details.append(err.get("message") or f"{err.get('field', '')} {err.get('code', '')}".strip())
        else:
            details.append(str(err))
    return message + (f" ({'; '.join(d for d in details if d)})" if details else "")
