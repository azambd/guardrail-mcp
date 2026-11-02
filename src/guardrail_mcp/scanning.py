"""Secret detection and redaction.

Two jobs: stop the agent from writing credentials into issues, comments or
commits, and stop credentials that already live in a repository from reaching
the model's context when it reads files or issues.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

# Patterns for credentials that commonly leak into tickets and commits.
# Ordered most specific first, so the most precise label wins.
DEFAULT_PATTERNS: dict[str, str] = {
    "github_token": r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b",
    "anthropic_api_key": r"\bsk-ant-[A-Za-z0-9_\-]{20,}",
    "openai_api_key": r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}",
    "aws_access_key_id": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    "slack_token": r"\bxox[abprs]-[A-Za-z0-9\-]{10,}",
    "private_key": r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----",
    "jwt": r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
    "bearer_header": r"(?i)\bauthorization:\s*bearer\s+[A-Za-z0-9._\-]{20,}",
}


class SecretScanner:
    def __init__(self, extra_patterns: Iterable[str] = ()) -> None:
        patterns = dict(DEFAULT_PATTERNS)
        for i, pattern in enumerate(extra_patterns):
            patterns[f"custom_{i + 1}"] = pattern
        self._patterns = [(label, re.compile(p)) for label, p in patterns.items()]

    def find(self, text: str) -> list[str]:
        """Return the labels of every secret type found in ``text``."""
        return [label for label, rx in self._patterns if rx.search(text)]

    def redact(self, text: str) -> tuple[str, int]:
        """Replace secrets with ``[REDACTED:<label>]``. Returns (text, count)."""
        total = 0
        for label, rx in self._patterns:
            text, n = rx.subn(f"[REDACTED:{label}]", text)
            total += n
        return text, total

    def redact_deep(self, value: Any) -> tuple[Any, int]:
        """Redact every string inside a JSON-like structure."""
        if isinstance(value, str):
            return self.redact(value)
        if isinstance(value, list):
            out, total = [], 0
            for item in value:
                clean, n = self.redact_deep(item)
                out.append(clean)
                total += n
            return out, total
        if isinstance(value, dict):
            out_d, total = {}, 0
            for key, item in value.items():
                clean, n = self.redact_deep(item)
                out_d[key] = clean
                total += n
            return out_d, total
        return value, 0


def as_text(value: Any) -> str:
    """Flatten an argument (string or list of strings) for scanning."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return "\n".join(str(v) for v in value)
    return str(value)
