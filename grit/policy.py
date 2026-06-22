"""Deterministic, first-match policy engine for tool calls.

Policy config:
{
  "default_action": "deny",
  "rules": [
    {"id": "no-deletes", "tools": ["demo__delete_*"], "action": "deny",
     "reason": "destructive ops are forbidden"},
    {"id": "big-transfer", "tools": ["demo__transfer_money"],
     "where": [{"path": "amount", "gt": 1000}], "action": "deny"},
    {"id": "mid-transfer", "tools": ["demo__transfer_money"],
     "where": [{"path": "amount", "gt": 50}], "action": "approve"},
    {"id": "search", "tools": ["demo__search_docs"], "action": "allow",
     "rate_limit": {"max_calls": 5, "window_seconds": 60}},
    {"id": "rest", "tools": ["*"], "action": "allow"}
  ]
}

A rule matches when the tool name matches any glob in `tools` AND every
matcher in `where` passes. A matcher whose `path` is missing in the
arguments does NOT pass. Supported matcher keys:
regex, not_regex, eq, gt, gte, lt, lte, max_len.
"""
from __future__ import annotations

import collections
import fnmatch
import re
import time
from dataclasses import dataclass
from typing import Any, Optional

ALLOW = "allow"
DENY = "deny"
APPROVE = "approve"
VALID_ACTIONS = {ALLOW, DENY, APPROVE}


class PolicyError(ValueError):
    pass


@dataclass
class Decision:
    action: str
    rule_id: Optional[str]
    reason: str


def _resolve(args: Any, path: str) -> tuple[bool, Any]:
    cur = args
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return False, None
    return True, cur


def _as_number(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return None


def _matcher_passes(matcher: dict, args: dict) -> bool:
    path = matcher.get("path")
    if not path:
        raise PolicyError(f"matcher missing 'path': {matcher!r}")
    found, value = _resolve(args, path)
    if not found:
        return False
    if "regex" in matcher and not re.search(matcher["regex"], str(value)):
        return False
    if "not_regex" in matcher and re.search(matcher["not_regex"], str(value)):
        return False
    if "eq" in matcher and value != matcher["eq"]:
        return False
    if "max_len" in matcher and len(str(value)) > matcher["max_len"]:
        return False
    for key in ("gt", "gte", "lt", "lte"):
        if key in matcher:
            num = _as_number(value)
            bound = _as_number(matcher[key])
            if num is None or bound is None:
                return False
            if key == "gt" and not num > bound:
                return False
            if key == "gte" and not num >= bound:
                return False
            if key == "lt" and not num < bound:
                return False
            if key == "lte" and not num <= bound:
                return False
    return True


class PolicyEngine:
    def __init__(self, config: dict):
        self.default_action = config.get("default_action", DENY)
        if self.default_action not in VALID_ACTIONS:
            raise PolicyError(f"invalid default_action: {self.default_action}")
        self.rules: list[dict] = config.get("rules", [])
        for i, rule in enumerate(self.rules):
            if rule.get("action") not in VALID_ACTIONS:
                raise PolicyError(f"rule #{i} has invalid action: {rule.get('action')!r}")
        # rule index -> recent call timestamps (for rate limits)
        self._buckets: dict[int, collections.deque] = collections.defaultdict(collections.deque)

    def evaluate(self, tool: str, arguments: dict, now: Optional[float] = None) -> Decision:
        now = time.time() if now is None else now
        for idx, rule in enumerate(self.rules):
            globs = rule.get("tools", ["*"])
            if not any(fnmatch.fnmatchcase(tool, g) for g in globs):
                continue
            if not all(_matcher_passes(m, arguments) for m in rule.get("where", [])):
                continue
            rule_id = rule.get("id", f"rule-{idx}")
            action = rule["action"]
            limit = rule.get("rate_limit")
            if action == ALLOW and limit:
                bucket = self._buckets[idx]
                cutoff = now - float(limit["window_seconds"])
                while bucket and bucket[0] <= cutoff:
                    bucket.popleft()
                if len(bucket) >= int(limit["max_calls"]):
                    return Decision(
                        DENY, rule_id,
                        f"rate limit exceeded: {limit['max_calls']} calls "
                        f"per {limit['window_seconds']}s for rule '{rule_id}'",
                    )
                bucket.append(now)
            return Decision(action, rule_id, rule.get("reason", f"matched rule '{rule_id}'"))
        return Decision(self.default_action, None, "no rule matched; default action applied")
