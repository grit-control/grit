"""Flight Recorder + deterministic Replay.

The two worst pains in agent development are non-reproducibility ("it failed,
I reran it, it worked") and finding the divergence step in a long run. The
recorder captures every tool call and (redacted) result per session; the
replay server then serves those recorded responses back to an agent re-run,
making debugging deterministic and free — no live tools touched, no side
effects, no API spend.

Also the substrate for the cost meter: tool results are context the agent
pays for on every subsequent step. We meter that flow.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
import threading
import time
from collections import defaultdict, deque
from typing import Optional, TextIO

from .jsonrpc import (METHOD_NOT_FOUND, error_response, read_message,
                      response, write_message)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS recordings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  ts REAL NOT NULL,
  tool TEXT NOT NULL,
  arguments TEXT NOT NULL,
  args_hash TEXT NOT NULL,
  result TEXT,
  status TEXT NOT NULL,
  failure_class TEXT,
  latency_ms INTEGER,
  tokens_in INTEGER NOT NULL DEFAULT 0,
  tokens_out INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_rec_session ON recordings(session_id, seq);
"""


def estimate_tokens(text: str) -> int:
    """Rough but useful: ~4 chars per token."""
    return max(1, len(text) // 4) if text else 0


def args_fingerprint(arguments: dict) -> str:
    canonical = json.dumps(arguments, separators=(",", ":"),
                           ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


class Recorder:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=15000")
        return conn

    def record(self, session_id: str, seq: int, tool: str, arguments: dict,
               result: Optional[dict], status: str,
               failure_class: Optional[str] = None,
               latency_ms: Optional[int] = None,
               ts: Optional[float] = None) -> tuple[int, int]:
        args_text = json.dumps(arguments, separators=(",", ":"),
                               ensure_ascii=False, sort_keys=True)
        result_text = (json.dumps(result, separators=(",", ":"),
                                  ensure_ascii=False)
                       if result is not None else None)
        tokens_in = estimate_tokens(args_text)
        tokens_out = estimate_tokens(result_text or "")
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO recordings (session_id, seq, ts, tool, arguments,"
                " args_hash, result, status, failure_class, latency_ms,"
                " tokens_in, tokens_out) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (session_id, seq, time.time() if ts is None else ts, tool,
                 args_text, args_fingerprint(arguments), result_text, status,
                 failure_class, latency_ms, tokens_in, tokens_out),
            )
        return tokens_in, tokens_out

    def sessions(self) -> list[dict]:
        query = """
        SELECT session_id, MIN(ts) AS started, COUNT(*) AS calls,
               SUM(CASE WHEN failure_class IS NOT NULL THEN 1 ELSE 0 END)
                   AS failures,
               SUM(tokens_in + tokens_out) AS est_tokens
        FROM recordings GROUP BY session_id ORDER BY started DESC
        """
        with self._connect() as conn:
            return [dict(r) for r in conn.execute(query).fetchall()]

    def trace(self, session_id: str) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM recordings WHERE session_id=? ORDER BY seq",
                (session_id,)).fetchall()
        return [dict(r) for r in rows]

    def records(self, session_id: Optional[str] = None,
               limit: Optional[int] = None) -> list[dict]:
        """All recordings in chronological order (ts, then seq) — the
        backtest substrate."""
        where = "WHERE session_id=?" if session_id else ""
        params: tuple = (session_id,) if session_id else ()
        lim = f" LIMIT {int(limit)}" if limit is not None else ""
        query = f"SELECT * FROM recordings {where} ORDER BY ts, seq{lim}"
        with self._connect() as conn:
            return [dict(r) for r in conn.execute(query, params).fetchall()]

    def costs(self, session_id: Optional[str] = None,
              usd_per_1m_tokens: float = 3.0) -> list[dict]:
        """Estimated context cost of tool traffic, grouped per tool."""
        where = "WHERE session_id=?" if session_id else ""
        params = (session_id,) if session_id else ()
        query = f"""
        SELECT tool, COUNT(*) AS calls,
               SUM(tokens_in) AS tokens_in, SUM(tokens_out) AS tokens_out
        FROM recordings {where} GROUP BY tool ORDER BY tokens_out DESC
        """
        with self._connect() as conn:
            rows = [dict(r) for r in conn.execute(query, params).fetchall()]
        for row in rows:
            total = (row["tokens_in"] or 0) + (row["tokens_out"] or 0)
            row["est_usd"] = round(total / 1_000_000 * usd_per_1m_tokens, 4)
        return rows


class ReplayServer:
    """A stdio MCP server that serves recorded responses back to an agent.

    Matching: exact (tool + canonical args hash) first; if the agent calls
    the same tool with different arguments, the next unconsumed recording
    for that tool is served and the step is flagged as a DIVERGENCE; if
    nothing is left to serve, a replay-miss error result is returned
    (in --strict mode every divergence is also a miss).
    """

    def __init__(self, recorder: Recorder, session_id: str,
                 strict: bool = False):
        rows = [r for r in recorder.trace(session_id) if r["result"]]
        if not rows:
            raise ValueError(f"session '{session_id}' has no recorded results")
        self.session_id = session_id
        self.strict = strict
        self.divergences: list[str] = []
        self.misses: list[str] = []
        self._by_tool: dict[str, deque] = defaultdict(deque)
        for row in rows:
            self._by_tool[row["tool"]].append(row)
        self._tools = sorted(self._by_tool)

    # ---- MCP plumbing ----

    def handle_message(self, msg: dict) -> Optional[dict]:
        method = msg.get("method")
        req_id = msg.get("id")
        if method is None or method.startswith("notifications/"):
            return None
        if method == "initialize":
            return response(req_id, {
                "protocolVersion": (msg.get("params") or {}).get(
                    "protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": f"grit-replay[{self.session_id}]",
                               "version": "replay"},
            })
        if method == "ping":
            return response(req_id, {})
        if method == "tools/list":
            tools = [{"name": t,
                      "description": f"replayed from session {self.session_id}",
                      "inputSchema": {"type": "object"}} for t in self._tools]
            return response(req_id, {"tools": tools})
        if method == "tools/call":
            params = msg.get("params") or {}
            return response(req_id, self._serve(params.get("name", ""),
                                                params.get("arguments") or {}))
        return error_response(req_id, METHOD_NOT_FOUND,
                              f"replay server: {method} not supported")

    def _miss(self, note: str) -> dict:
        self.misses.append(note)
        return {"content": [{"type": "text",
                             "text": f"GRIT replay miss: {note}"}],
                "isError": True}

    def _serve(self, tool: str, arguments: dict) -> dict:
        queue = self._by_tool.get(tool)
        if not queue:
            return self._miss(f"no recorded responses left for '{tool}'")
        fingerprint = args_fingerprint(arguments)
        exact_idx = next((i for i, r in enumerate(queue)
                          if r["args_hash"] == fingerprint), None)
        if exact_idx is not None:
            row = queue[exact_idx]
            del queue[exact_idx]
        else:
            note = (f"DIVERGENCE at '{tool}': live args {arguments!r} differ "
                    f"from every remaining recording")
            self.divergences.append(note)
            print(f"[grit-replay] {note}", file=sys.stderr, flush=True)
            if self.strict:
                return self._miss(note)
            row = queue.popleft()
        return json.loads(row["result"])

    def serve_stdio(self, stdin: Optional[TextIO] = None,
                    stdout: Optional[TextIO] = None) -> None:
        stdin = stdin or sys.stdin
        stdout = stdout or sys.stdout
        while True:
            msg = read_message(stdin)
            if msg is None:
                break
            reply = self.handle_message(msg)
            if reply is not None:
                write_message(stdout, reply)
        print(f"[grit-replay] session {self.session_id}: "
              f"{len(self.divergences)} divergences, "
              f"{len(self.misses)} misses", file=sys.stderr, flush=True)
