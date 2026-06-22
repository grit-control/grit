"""Flow guard: entity-level egress control for the lethal trifecta.

The only defense against prompt injection that the security community
considers robust is limiting what a compromised agent can DO, not filtering
what it reads. The trifecta: (1) access to private data, (2) exposure to
untrusted content, (3) an external channel to write to. Text filters miss
paraphrased attacks; this guard doesn't try to read minds — it tracks
*verbatim secrets* (API keys, AWS keys, card numbers, SSNs) that entered the
session from a private source and escalates any call that carries one of
them toward an external sink. A paraphrased API key stops being an API key,
so the verbatim tier is the high-precision tier — precision over theater.

Trust zones are declared per upstream (in `grit.json`):

  "upstreams": [
    {"name": "db",   ..., "trust": ["private_source"]},
    {"name": "web",  ..., "trust": ["untrusted_source"]},
    {"name": "mail", ..., "trust": ["external_sink", "untrusted_source"]}
  ],
  "flow": {"action": "approve"}          // or "deny"; "zones" may add more

Deliberately NOT here (honesty): session-wide taint ("any tainted session
loses egress") fires on nearly every real workflow and trains people to
rubber-stamp; paraphrase/semantic leak detection is unsolved. This guard is
narrow so that when it fires, it's worth a human's attention.
"""
from __future__ import annotations

import re
from typing import Any, Optional

from .redact import BUILTIN_PATTERNS

PRIVATE_SOURCE = "private_source"
UNTRUSTED_SOURCE = "untrusted_source"
EXTERNAL_SINK = "external_sink"
VALID_ZONES = {PRIVATE_SOURCE, UNTRUSTED_SOURCE, EXTERNAL_SINK}

# verbatim-entity patterns only — things that are useless when paraphrased
_ENTITY_KEYS = ("aws_key", "api_key", "credit_card", "us_ssn")
MIN_ENTITY_LEN = 8
_SEPARATOR = "__"


class FlowError(ValueError):
    pass


def _flatten_strings(obj: Any, acc: list[str]) -> None:
    if isinstance(obj, str):
        acc.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _flatten_strings(v, acc)
    elif isinstance(obj, list):
        for v in obj:
            _flatten_strings(v, acc)


def _blob(obj: Any) -> str:
    strings: list[str] = []
    _flatten_strings(obj, strings)
    return "\n".join(strings)


def _mask(secret: str) -> str:
    return f"{secret[:4]}…({len(secret)} chars)"


class FlowGuard:
    """Session-scoped egress guard.

    `observe_result()` AFTER a call executed (raw result, before redaction);
    `check()` BEFORE an outgoing call executes. Secrets live in process
    memory only — nothing persists, nothing leaves the gateway."""

    def __init__(self, zones: dict[str, Any], action: str = "approve"):
        if action not in ("approve", "deny"):
            raise FlowError(f"flow action must be 'approve' or 'deny', "
                            f"got {action!r}")
        self.action = action
        self.zones: dict[str, frozenset] = {}
        for upstream, declared in (zones or {}).items():
            zone = frozenset(declared)
            unknown = zone - VALID_ZONES
            if unknown:
                raise FlowError(
                    f"unknown trust zone(s) {sorted(unknown)} for upstream "
                    f"'{upstream}'; valid: {sorted(VALID_ZONES)}")
            self.zones[upstream] = zone
        # secret value -> the tool whose result first carried it
        self._secrets: dict[str, str] = {}
        self.untrusted_from: Optional[str] = None
        self._patterns = [re.compile(BUILTIN_PATTERNS[k])
                          for k in _ENTITY_KEYS]

    def _zone(self, tool: str) -> frozenset:
        upstream = tool.split(_SEPARATOR, 1)[0]
        return self.zones.get(upstream, frozenset())

    @property
    def secrets_held(self) -> int:
        return len(self._secrets)

    # ---- learning (executed calls only) ----

    def observe_result(self, tool: str, result: Any) -> None:
        zone = self._zone(tool)
        if UNTRUSTED_SOURCE in zone and self.untrusted_from is None:
            self.untrusted_from = tool
        if PRIVATE_SOURCE in zone and result is not None:
            blob = _blob(result)
            for rx in self._patterns:
                for match in rx.findall(blob):
                    if len(match) >= MIN_ENTITY_LEN:
                        self._secrets.setdefault(match, tool)

    # ---- enforcement ----

    def check(self, tool: str, arguments: dict) -> Optional[str]:
        """Reason string if this call carries a known secret to an external
        sink; None otherwise."""
        if EXTERNAL_SINK not in self._zone(tool):
            return None
        blob = _blob(arguments)
        for secret, source in self._secrets.items():
            if secret in blob:
                reason = (f"flow guard: arguments carry a secret "
                          f"'{_mask(secret)}' read from {source} "
                          f"(private source) toward an external sink")
                if self.untrusted_from:
                    reason += (f"; session also ingested untrusted content "
                               f"from {self.untrusted_from} — "
                               f"lethal trifecta complete")
                return reason
        return None
