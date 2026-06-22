"""GRIT Risk Engine: scores every tool call 0-100 against behavioral
baselines accumulated from the call history.

This is the part of GRIT that gets *better with every call that flows
through it* — and the part that static policies cannot replace. Policies
catch what you predicted; the risk engine catches what you didn't:

- an agent that learned to keep transfers just under the approval limit
  (numeric anomaly vs. the historical distribution of that argument);
- an agent that suddenly starts emailing API keys around
  (secrets appearing in arguments of an otherwise allowed tool);
- a runaway loop hammering one tool (velocity burst);
- an agent stuck retrying the exact same call (stuck loop);
- a tool nobody has ever called before (novelty).

Deterministic, explainable (every score comes with named factors),
stdlib-only. Cross-deployment anomaly signatures (the "Risk Network")
are the commercial layer built on top of this interface.
"""
from __future__ import annotations

import collections
import json
import re
import statistics
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from .redact import BUILTIN_PATTERNS

DESTRUCTIVE_VERBS = ("delete", "drop", "remove", "destroy", "truncate",
                     "kill", "terminate", "wipe", "purge", "revoke")
MUTATING_VERBS = ("write", "update", "create", "send", "post", "transfer",
                  "pay", "execute", "run", "insert", "upload", "move",
                  "grant", "deploy", "merge", "push", "charge", "refund")

SENSITIVE_TOKENS = re.compile(
    r"(/etc/|\.env\b|\.ssh|id_rsa|\bprod(uction)?\b|\bsecrets?\b|passwd"
    r"|--force\b|rm -rf|DROP TABLE|sudo\b)", re.IGNORECASE)

# emails/phones are normal in tool args; only true secrets raise risk
_SECRET_PATTERNS = [re.compile(BUILTIN_PATTERNS[k])
                    for k in ("aws_key", "api_key", "credit_card", "us_ssn")]

# weights
W_DESTRUCTIVE = 40
W_MUTATING = 15
W_NOVELTY = 10
W_ANOMALY = 35
W_BURST = 25
W_SECRETS = 30
W_SENSITIVE = 25
W_STUCK = 25

MIN_BASELINE = 5          # observations of a numeric arg before z-scoring
ANOMALY_Z = 3.0
BURST_WINDOW_S = 60.0
BURST_CALLS = 12
STUCK_REPEATS = 3         # identical (tool, args) calls in a row => stuck loop
HISTORY_CAP = 1000        # per (tool, arg) numeric history cap

LEVELS = ((85, "critical"), (60, "high"), (30, "medium"), (0, "low"))


@dataclass
class RiskAssessment:
    score: int
    level: str
    factors: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return f"risk {self.score}/100 ({self.level}): " + \
            ("; ".join(self.factors) if self.factors else "no risk factors")


def _level(score: int) -> str:
    for threshold, name in LEVELS:
        if score >= threshold:
            return name
    return "low"


def _flatten_strings(obj: Any, acc: list[str]) -> None:
    if isinstance(obj, str):
        acc.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _flatten_strings(v, acc)
    elif isinstance(obj, list):
        for v in obj:
            _flatten_strings(v, acc)


def _args_fingerprint(arguments: dict) -> str:
    return json.dumps(arguments, separators=(",", ":"), ensure_ascii=False,
                      sort_keys=True)


def _numeric_args(arguments: dict, prefix: str = "") -> list[tuple[str, float]]:
    out = []
    for key, value in arguments.items():
        path = f"{prefix}{key}"
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            out.append((path, float(value)))
        elif isinstance(value, dict):
            out.extend(_numeric_args(value, prefix=f"{path}."))
    return out


class RiskEngine:
    """Holds behavioral baselines and scores calls against them.

    Usage: `assess()` BEFORE the call executes; `observe()` only after a
    call actually executed (so blocked calls don't poison baselines)."""

    def __init__(self, audit=None):
        self._numeric: dict[tuple[str, str], collections.deque] = \
            collections.defaultdict(lambda: collections.deque(maxlen=HISTORY_CAP))
        self._seen_tools: set[str] = set()
        self._recent: dict[str, collections.deque] = \
            collections.defaultdict(lambda: collections.deque(maxlen=BURST_CALLS * 4))
        # trailing fingerprints of executed calls per tool (stuck-loop detector)
        self._last_args: dict[str, collections.deque] = \
            collections.defaultdict(lambda: collections.deque(maxlen=STUCK_REPEATS * 4))
        if audit is not None:
            self._warm_start(audit)

    def _warm_start(self, audit) -> None:
        """Rebuild baselines from the audit history (executed calls only)."""
        for row in reversed(audit.recent(limit=HISTORY_CAP * 5)):
            if not str(row["status"]).startswith("executed"):
                continue
            try:
                arguments = json.loads(row["arguments"])
            except (json.JSONDecodeError, TypeError):
                continue
            self.observe(row["tool"], arguments, ts=row["ts"])

    # ---- learning ----

    def observe(self, tool: str, arguments: dict,
                ts: Optional[float] = None) -> None:
        ts = time.time() if ts is None else ts
        self._seen_tools.add(tool)
        self._recent[tool].append(ts)
        self._last_args[tool].append(_args_fingerprint(arguments))
        for path, value in _numeric_args(arguments):
            self._numeric[(tool, path)].append(value)

    # ---- scoring ----

    def assess(self, tool: str, arguments: dict,
               now: Optional[float] = None) -> RiskAssessment:
        now = time.time() if now is None else now
        score = 0
        factors: list[str] = []
        lowered = tool.lower()

        if any(verb in lowered for verb in DESTRUCTIVE_VERBS):
            score += W_DESTRUCTIVE
            factors.append("destructive operation by name")
        elif any(verb in lowered for verb in MUTATING_VERBS):
            score += W_MUTATING
            factors.append("mutating operation by name")

        if tool not in self._seen_tools:
            score += W_NOVELTY
            factors.append("first ever call of this tool")

        for path, value in _numeric_args(arguments):
            history = self._numeric.get((tool, path))
            if not history or len(history) < MIN_BASELINE:
                continue
            med = statistics.median(history)
            mad = statistics.median(abs(x - med) for x in history)
            scale = 1.4826 * mad if mad > 0 else max(abs(med) * 0.1, 1e-9)
            z = abs(value - med) / scale
            if z >= ANOMALY_Z:
                score += W_ANOMALY
                factors.append(
                    f"'{path}'={value} deviates from baseline "
                    f"(median {med}, z={z:.1f}, n={len(history)})")
                break  # one anomaly bonus per call

        recent = self._recent.get(tool)
        if recent:
            in_window = sum(1 for t in recent if t > now - BURST_WINDOW_S)
            if in_window >= BURST_CALLS:
                score += W_BURST
                factors.append(
                    f"velocity burst: {in_window} calls in {int(BURST_WINDOW_S)}s")

        # stuck loop: this exact call already executed N times in a row
        trail = self._last_args.get(tool)
        if trail:
            fingerprint = _args_fingerprint(arguments)
            repeats = 0
            for past in reversed(trail):
                if past != fingerprint:
                    break
                repeats += 1
            if repeats >= STUCK_REPEATS:
                score += W_STUCK
                factors.append(
                    f"stuck loop: identical call already executed "
                    f"{repeats} times in a row")

        strings: list[str] = []
        _flatten_strings(arguments, strings)
        blob = " ".join(strings)
        if any(rx.search(blob) for rx in _SECRET_PATTERNS):
            score += W_SECRETS
            factors.append("arguments contain secret/PII-looking data")
        if SENSITIVE_TOKENS.search(blob):
            score += W_SENSITIVE
            factors.append("arguments reference sensitive targets")

        score = min(score, 100)
        return RiskAssessment(score, _level(score), factors)
