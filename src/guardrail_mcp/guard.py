"""The guard: every tool call passes through here before it touches GitHub.

Pipeline for each call:

1. Policy check: tool enabled, repository, branch, path, PR base, text size,
   secrets in the arguments. A violation is logged and returned to the agent
   as a clear denial with the rule id.
2. Reads run, secrets in the result are redacted, and the call is logged.
3. Writes go through, in order: idempotent replay (an identical successful
   write inside the window returns the original result instead of repeating
   it), dry run, the per-session write budget, the human approval gate, and a
   write-ahead audit record. If the intent cannot be logged, the write does
   not happen. The outcome is logged after the call.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
from collections.abc import Awaitable, Callable
from typing import Any

from mcp.server.mcpserver.exceptions import ToolError

from .audit import AuditLog, canonical
from .catalog import CATALOG, ToolSpec
from .github import GitHubError
from .policy import Policy, Violation
from .scanning import SecretScanner, as_text
from .state import StateStore

try:
    from opentelemetry import trace as _otel_trace
except ImportError:  # pragma: no cover
    _otel_trace = None

log = logging.getLogger("guardrail_mcp.guard")

# Result fields worth keeping in the audit log. Everything else stays out so
# the log records what happened without copying repository content.
_SUMMARY_KEYS = (
    "number", "html_url", "ref", "sha", "commit_sha", "path", "branch", "state",
    "merged", "draft", "count", "overall", "run_id", "head", "base", "status",
)


class AuditUnavailable(ToolError):
    """The audit log could not be written, so the action is refused."""


def hash_args(tool: str, args: dict[str, Any]) -> str:
    return hashlib.sha256(canonical({"tool": tool, "args": args}).encode("utf-8")).hexdigest()


class Guard:
    def __init__(
        self,
        policy: Policy,
        audit: AuditLog,
        state: StateStore,
        *,
        agent_id: str = "agent",
        session_id: str | None = None,
    ) -> None:
        self.policy = policy
        self.audit = audit
        self.state = state
        self.agent_id = agent_id
        self.session_id = session_id or "s_" + secrets.token_hex(4)
        self.scanner = SecretScanner(policy.content.extra_secret_patterns)
        self.writes_used = 0

    # ================================================================ checks

    def evaluate(self, spec: ToolSpec, args: dict[str, Any]) -> Violation | None:
        p = self.policy
        if p.permission(spec.name) == "deny":
            return Violation("tools.allow", f"tool {spec.name!r} is not enabled by policy")

        if spec.repo_arg:
            repo = str(args.get(spec.repo_arg) or "")
            if (v := p.check_repo(repo)) is not None:
                return v

        for name in spec.branch_args:
            if args.get(name) and (v := p.check_branch(str(args[name]))) is not None:
                return v

        for name in spec.path_args:
            if args.get(name) is not None and (v := p.check_path(str(args[name]), write=spec.is_write)) is not None:
                return v

        if spec.base_arg and args.get(spec.base_arg) and (v := p.check_base(str(args[spec.base_arg]))) is not None:
            return v

        if spec.is_write:
            for name in spec.text_args:
                text = as_text(args.get(name))
                if len(text) > p.limits.max_text_chars:
                    return Violation(
                        "limits.max_text_chars",
                        f"argument {name!r} is {len(text)} characters; the limit is {p.limits.max_text_chars}",
                    )
                if (v := self._secret_violation(name, text)) is not None:
                    return v
            for name in spec.file_args:
                text = as_text(args.get(name))
                size = len(text.encode("utf-8"))
                if size > p.limits.max_file_bytes:
                    return Violation(
                        "limits.max_file_bytes",
                        f"argument {name!r} is {size} bytes; the limit is {p.limits.max_file_bytes}",
                    )
                if (v := self._secret_violation(name, text)) is not None:
                    return v
        return None

    def _secret_violation(self, arg: str, text: str) -> Violation | None:
        if not self.policy.content.block_secrets or not text:
            return None
        found = self.scanner.find(text)
        if found:
            return Violation(
                "content.block_secrets",
                f"argument {arg!r} contains what looks like a credential ({', '.join(found)}); remove it and retry",
            )
        return None

    # ================================================================ run

    async def run(
        self,
        tool: str,
        args: dict[str, Any],
        execute: Callable[[], Awaitable[dict[str, Any]]],
        *,
        ctx: Any = None,
        dry_run: bool = False,
        preview: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        spec = CATALOG[tool]
        started = time.monotonic()
        args_hash = hash_args(tool, args)
        event: dict[str, Any] = {
            "session": self.session_id,
            "agent": self.agent_id,
            "request_id": _request_id(ctx),
            "tool": tool,
            "kind": spec.kind,
            "repo": args.get(spec.repo_arg) if spec.repo_arg else None,
            "args": self._audit_args(spec, args),
            "args_sha256": args_hash,
        }

        violation = self.evaluate(spec, args)
        if violation is not None:
            self._record(event, "deny", started, rule=violation.rule, reason=violation.message)
            raise ToolError(
                f"DENIED by policy [{violation.rule}]: {violation.message}. "
                "Nothing was changed and the attempt was logged. Do not work around this rule; "
                "call describe_permissions to see what is allowed, or ask the user."
            )

        if not spec.is_write:
            result = await self._execute(event, "allow", started, execute)
            return self._redact_read(result, event)

        return await self._run_write(spec, args, args_hash, event, started, execute, dry_run, preview)

    async def _run_write(
        self,
        spec: ToolSpec,
        args: dict[str, Any],
        args_hash: str,
        event: dict[str, Any],
        started: float,
        execute: Callable[[], Awaitable[dict[str, Any]]],
        dry_run: bool,
        preview: dict[str, Any] | None,
    ) -> dict[str, Any]:
        p = self.policy

        replay = self.state.recent_result(args_hash, p.limits.idempotency_window_seconds)
        if replay is not None:
            self._record(event, "replayed", started, reason="identical write already succeeded inside the idempotency window")
            return {
                **replay,
                "idempotent_replay": True,
                "note": "An identical call already succeeded moments ago, so the original result is returned "
                "and the write was not repeated.",
            }

        if dry_run or p.mode == "dry_run":
            reason = "server is in dry_run mode" if p.mode == "dry_run" else "dry_run requested by the agent"
            self._record(event, "dry_run", started, reason=reason)
            return {
                "status": "dry_run",
                "tool": spec.name,
                "would_perform": self._safe(preview or {}),
                "note": f"Preview only, nothing was changed ({reason}).",
            }

        limit = p.limits.max_writes_per_session
        if self.writes_used >= limit:
            message = f"this session has used its {limit} write(s)"
            self._record(event, "deny", started, rule="limits.max_writes_per_session", reason=message)
            raise ToolError(
                f"DENIED by policy [limits.max_writes_per_session]: {message}. "
                "Stop and summarize your progress for the user."
            )

        approval = None
        if p.permission(spec.name) == "approval":
            approval = self.state.granted_approval(args_hash)
            if approval is None:
                request = self.state.request_approval(
                    args_hash=args_hash,
                    tool=spec.name,
                    repo=event["repo"],
                    args=event["args"],
                    ttl=p.limits.approval_ttl_seconds,
                    session=self.session_id,
                )
                minutes = max(1, int((request.expires_at - time.time()) // 60))
                self._record(
                    event, "approval_required", started, reason="tool requires human approval", approval_id=request.id
                )
                raise ToolError(
                    f"APPROVAL REQUIRED: {spec.name} needs human sign-off. Request {request.id} is pending "
                    f"(expires in about {minutes} min). Nothing was changed. Ask the user to run "
                    f"`guardrail-mcp approvals approve {request.id}`, then call {spec.name} again "
                    "with exactly the same arguments."
                )
            event["approval_id"] = approval.id

        # Write-ahead: if the intent cannot be logged, the write does not happen.
        self._record(event, "allow", started, phase="intent")
        self.writes_used += 1
        result = await self._execute(event, "allow", started, execute, phase="result")
        if approval is not None:
            self.state.consume(approval.id)
        self.state.save_result(args_hash, spec.name, result)
        return {"status": "ok", **result}

    async def _execute(
        self,
        event: dict[str, Any],
        decision: str,
        started: float,
        execute: Callable[[], Awaitable[dict[str, Any]]],
        *,
        phase: str | None = None,
    ) -> dict[str, Any]:
        try:
            result = await execute()
        except (GitHubError, ToolError) as exc:
            self._record(event, decision, started, outcome="error", error=str(exc), phase=phase)
            raise ToolError(str(exc)) from exc
        except Exception as exc:
            self._record(event, decision, started, outcome="error", error=f"{type(exc).__name__}", phase=phase)
            raise
        self._record(event, decision, started, outcome="ok", result=_summarize(result), phase=phase)
        return result

    # ================================================================ helpers

    def _redact_read(self, result: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
        if not self.policy.content.redact_secrets_in_reads:
            return result
        clean, count = self.scanner.redact_deep(result)
        if count:
            self._record(
                event, "redacted", time.monotonic(), reason=f"{count} secret(s) removed from the result before it reached the agent"
            )
            clean["_guardrail"] = {
                "redacted_secrets": count,
                "note": "Credentials in this content were replaced with [REDACTED:<type>] by policy.",
            }
        return clean

    def _audit_args(self, spec: ToolSpec, args: dict[str, Any]) -> dict[str, Any]:
        """Arguments as they are stored: secrets redacted, long text truncated, file bodies hashed."""
        max_chars = self.policy.audit.max_arg_chars
        stored: dict[str, Any] = {}
        for key, value in args.items():
            if key in spec.file_args and isinstance(value, str):
                stored[key] = {
                    "bytes": len(value.encode("utf-8")),
                    "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
                }
                continue
            stored[key] = self._safe(value, max_chars)
        return stored

    def _safe(self, value: Any, max_chars: int | None = None) -> Any:
        max_chars = max_chars or self.policy.audit.max_arg_chars
        clean, _ = self.scanner.redact_deep(value)
        return _truncate(clean, max_chars)

    def _record(self, event: dict[str, Any], decision: str, started: float, **extra: Any) -> None:
        entry = {**event, "decision": decision, **{k: v for k, v in extra.items() if v is not None}}
        entry["duration_ms"] = round((time.monotonic() - started) * 1000, 1)
        _otel_annotate(entry)
        try:
            self.audit.append({k: v for k, v in entry.items() if v is not None})
        except Exception as exc:
            log.error("audit log write failed: %s", exc)
            raise AuditUnavailable(
                "The audit log could not be written, so this action was refused. Tell the user to check the audit path."
            ) from exc


def _request_id(ctx: Any) -> str | None:
    try:
        return str(ctx.request_id) if ctx is not None else None
    except Exception:
        return None


def _truncate(value: Any, max_chars: int) -> Any:
    if isinstance(value, str) and len(value) > max_chars:
        return f"{value[:max_chars]}... [{len(value)} chars]"
    if isinstance(value, list):
        return [_truncate(v, max_chars) for v in value]
    if isinstance(value, dict):
        return {k: _truncate(v, max_chars) for k, v in value.items()}
    return value


def _summarize(result: dict[str, Any]) -> dict[str, Any]:
    return {k: result[k] for k in _SUMMARY_KEYS if k in result and not isinstance(result[k], (dict, list))}


def _otel_annotate(entry: dict[str, Any]) -> None:
    """Attach the decision to the SDK's per-call OpenTelemetry span, if tracing is on."""
    if _otel_trace is None:
        return
    span = _otel_trace.get_current_span()
    if not span.is_recording():
        return
    attrs = {
        "guardrail.tool": entry["tool"],
        "guardrail.decision": entry["decision"],
        "guardrail.session": entry.get("session", ""),
    }
    for key in ("rule", "outcome", "repo", "approval_id", "phase"):
        if entry.get(key):
            attrs[f"guardrail.{key}"] = str(entry[key])
    span.add_event("guardrail.decision", attributes=attrs)
