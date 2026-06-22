"""Redact sensitive data (PII, secrets) from tool results before the
model ever sees them."""
from __future__ import annotations

import re
from typing import Any, Optional

BUILTIN_PATTERNS: dict[str, str] = {
    "email": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    "credit_card": r"\b(?:\d[ -]?){13,16}\b",
    "aws_key": r"\bAKIA[0-9A-Z]{16}\b",
    "api_key": r"\b(?:sk|pk|rk|key)-[A-Za-z0-9_\-]{16,}\b",
    "us_ssn": r"\b\d{3}-\d{2}-\d{4}\b",
}


class Redactor:
    def __init__(self, enabled: Optional[list[str]] = None,
                 custom: Optional[dict[str, str]] = None):
        patterns: dict[str, str] = {}
        names = list(BUILTIN_PATTERNS) if enabled is None else enabled
        for name in names:
            if name not in BUILTIN_PATTERNS:
                raise ValueError(f"unknown builtin redaction pattern: {name}")
            patterns[name] = BUILTIN_PATTERNS[name]
        patterns.update(custom or {})
        self._compiled = {name: re.compile(rx) for name, rx in patterns.items()}

    def redact_text(self, text: str) -> str:
        for name, rx in self._compiled.items():
            text = rx.sub(f"[REDACTED:{name}]", text)
        return text

    def redact(self, obj: Any) -> Any:
        """Recursively redact every string in a JSON-like structure."""
        if isinstance(obj, str):
            return self.redact_text(obj)
        if isinstance(obj, list):
            return [self.redact(item) for item in obj]
        if isinstance(obj, dict):
            return {key: self.redact(value) for key, value in obj.items()}
        return obj
