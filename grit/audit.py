"""Tamper-evident audit log + approval queue + ops stats, backed by SQLite.

Every audit row is chained: hash = sha256(canonical(row) + prev_hash).
Editing or deleting any historical row breaks the chain, which `verify()`
detects. WAL mode lets the gateway, CLI and dashboard share one DB file.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Optional

GENESIS = "0" * 64

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  tool TEXT NOT NULL,
  arguments TEXT NOT NULL,
  decision TEXT NOT NULL,
  rule_id TEXT,
  reason TEXT,
  status TEXT NOT NULL,
  failure_class TEXT,
  latency_ms INTEGER,
  risk_score INTEGER,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  tool TEXT NOT NULL,
  arguments TEXT NOT NULL,
  reason TEXT,
  risk_score INTEGER,
  status TEXT NOT NULL DEFAULT 'pending',
  decided_ts REAL,
  decided_by TEXT
);
CREATE TABLE IF NOT EXISTS controls (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_ts REAL NOT NULL,
  updated_by TEXT
);
"""


def _row_hash(ts: float, tool: str, arguments: str, decision: str,
              rule_id: Optional[str], reason: Optional[str], status: str,
              failure_class: Optional[str], latency_ms: Optional[int],
              risk_score: Optional[int], prev_hash: str) -> str:
    payload = json.dumps(
        [ts, tool, arguments, decision, rule_id or "", reason or "", status,
         failure_class or "", -1 if latency_ms is None else latency_ms,
         -1 if risk_score is None else risk_score, prev_hash],
        separators=(",", ":"), ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class VerifyResult:
    ok: bool
    rows: int
    broken_at: Optional[int] = None
    detail: str = ""


class AuditLog:
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

    # ---- audit chain ----

    def record(self, tool: str, arguments: dict, decision: str,
               rule_id: Optional[str], reason: Optional[str], status: str,
               latency_ms: Optional[int] = None,
               risk_score: Optional[int] = None,
               failure_class: Optional[str] = None,
               ts: Optional[float] = None) -> str:
        ts = time.time() if ts is None else ts
        args_text = json.dumps(arguments, separators=(",", ":"),
                               ensure_ascii=False, sort_keys=True)
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
            prev_hash = row["hash"] if row else GENESIS
            digest = _row_hash(ts, tool, args_text, decision, rule_id, reason,
                               status, failure_class, latency_ms, risk_score,
                               prev_hash)
            conn.execute(
                "INSERT INTO audit (ts, tool, arguments, decision, rule_id,"
                " reason, status, failure_class, latency_ms, risk_score,"
                " prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (ts, tool, args_text, decision, rule_id, reason, status,
                 failure_class, latency_ms, risk_score, prev_hash, digest),
            )
        return digest

    def verify(self) -> VerifyResult:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM audit ORDER BY id").fetchall()
        prev = GENESIS
        for row in rows:
            if row["prev_hash"] != prev:
                return VerifyResult(False, len(rows), row["id"],
                                    f"row {row['id']}: prev_hash mismatch (chain edited)")
            expected = _row_hash(row["ts"], row["tool"], row["arguments"],
                                 row["decision"], row["rule_id"], row["reason"],
                                 row["status"], row["failure_class"],
                                 row["latency_ms"], row["risk_score"],
                                 row["prev_hash"])
            if expected != row["hash"]:
                return VerifyResult(False, len(rows), row["id"],
                                    f"row {row['id']}: content hash mismatch (row tampered)")
            prev = row["hash"]
        return VerifyResult(True, len(rows), None, "chain intact")

    def recent(self, limit: int = 50) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def recent_since(self, last_id: int, limit: int = 200) -> list[dict]:
        """Rows newer than `last_id`, oldest first — the live-tail cursor."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM audit WHERE id > ? ORDER BY id ASC LIMIT ?",
                (last_id, limit)).fetchall()
        return [dict(r) for r in rows]

    def match_call(self, tool: str, arguments: str, status: str,
                   failure_class: Optional[str],
                   near_ts: Optional[float] = None) -> Optional[dict]:
        """Best-effort lookup of the audit row behind a flight-recorder call.

        The audit table has no session_id, so a recorded call is reconnected
        to its decision by (tool, canonical arguments, status, failure_class);
        when several match, the row with the closest ts wins. Read-only — it
        never touches the hash chain. ``arguments`` is the canonical text as
        stored by the recorder (sort_keys), so it matches the audit row
        verbatim. Returns the decision row (reason, risk_score, hash, rule_id)
        or None."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM audit WHERE tool=? AND arguments=? AND status=?"
                " AND failure_class IS ?",
                (tool, arguments, status, failure_class)).fetchall()
        if not rows:
            return None
        if near_ts is None:
            return dict(rows[-1])
        return dict(min(rows, key=lambda r: abs(r["ts"] - near_ts)))

    def stats(self) -> list[dict]:
        """Per-tool ops summary: volumes, failures, latency, risk."""
        query = """
        SELECT tool,
               COUNT(*) AS calls,
               SUM(CASE WHEN status LIKE 'executed%' THEN 1 ELSE 0 END) AS executed,
               SUM(CASE WHEN status IN ('blocked','approval_denied',
                                        'approval_timeout') THEN 1 ELSE 0 END) AS blocked,
               SUM(CASE WHEN status='error' THEN 1 ELSE 0 END) AS errors,
               CAST(AVG(latency_ms) AS INTEGER) AS avg_latency_ms,
               CAST(AVG(risk_score) AS INTEGER) AS avg_risk,
               MAX(risk_score) AS max_risk
        FROM audit GROUP BY tool ORDER BY calls DESC
        """
        with self._connect() as conn:
            return [dict(r) for r in conn.execute(query).fetchall()]

    def shadow_count(self) -> int:
        """Calls that observe mode executed but WOULD have held or denied."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM audit"
                " WHERE status='executed_shadow'").fetchone()
        return int(row["c"])

    def events_count(self, since_hours: float = 168.0) -> int:
        """Calls through the gateway in the window — the north-star number."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM audit WHERE ts > ?",
                (time.time() - since_hours * 3600.0,)).fetchone()
        return int(row["c"])

    def events_histogram(self, hours: int = 24,
                         now: Optional[float] = None) -> list[int]:
        """Calls per hour for the last `hours` hours, oldest bucket first."""
        now = time.time() if now is None else now
        buckets = [0] * hours
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT ts FROM audit WHERE ts > ?",
                (now - hours * 3600.0,)).fetchall()
        for row in rows:
            age = int((now - row["ts"]) // 3600.0)
            if 0 <= age < hours:
                buckets[hours - 1 - age] += 1
        return buckets

    def failure_breakdown(self) -> list[dict]:
        """Counts per failure class — the taxonomy view."""
        query = """
        SELECT failure_class, COUNT(*) AS count
        FROM audit WHERE failure_class IS NOT NULL
        GROUP BY failure_class ORDER BY count DESC
        """
        with self._connect() as conn:
            return [dict(r) for r in conn.execute(query).fetchall()]

    def drift(self, window_hours: float = 24.0,
              now: Optional[float] = None) -> list[dict]:
        """Compare per-tool behavior: last window vs. the window before it.

        Flags tools whose failure rate, latency, risk or volume shifted
        materially — the cheap canary for model-version drift."""
        now = time.time() if now is None else now
        window = window_hours * 3600.0
        query = """
        SELECT tool, COUNT(*) AS calls,
               AVG(CASE WHEN failure_class IS NOT NULL THEN 1.0 ELSE 0.0 END)
                   AS failure_rate,
               AVG(latency_ms) AS avg_latency, AVG(risk_score) AS avg_risk
        FROM audit WHERE ts > ? AND ts <= ? GROUP BY tool
        """
        with self._connect() as conn:
            current = {r["tool"]: dict(r) for r in
                       conn.execute(query, (now - window, now)).fetchall()}
            previous = {r["tool"]: dict(r) for r in
                        conn.execute(query, (now - 2 * window,
                                             now - window)).fetchall()}
        report = []
        for tool in sorted(set(current) | set(previous)):
            cur, prev = current.get(tool), previous.get(tool)
            flags = []
            if cur and prev:
                if (cur["failure_rate"] or 0) - (prev["failure_rate"] or 0) > 0.15:
                    flags.append("failure rate up")
                if prev["avg_latency"] and cur["avg_latency"] and \
                        cur["avg_latency"] > 2 * prev["avg_latency"]:
                    flags.append("latency 2x up")
                if (cur["avg_risk"] or 0) - (prev["avg_risk"] or 0) > 15:
                    flags.append("risk profile up")
                ratio = cur["calls"] / max(prev["calls"], 1)
                if ratio > 3 or ratio < 1 / 3:
                    flags.append("volume shift")
            elif cur and not prev:
                flags.append("new tool in this window")
            elif prev and not cur:
                flags.append("tool went silent")
            report.append({"tool": tool, "current": cur, "previous": prev,
                           "flags": flags})
        return report

    # ---- controls (kill switch & friends) ----

    def set_control(self, key: str, value: str, by: str = "cli") -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO controls (key, value, updated_ts, updated_by)"
                " VALUES (?,?,?,?) ON CONFLICT(key) DO UPDATE SET"
                " value=excluded.value, updated_ts=excluded.updated_ts,"
                " updated_by=excluded.updated_by",
                (key, value, time.time(), by),
            )

    def get_control(self, key: str, default: str = "") -> str:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM controls WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def set_paused(self, paused: bool, by: str = "cli") -> None:
        self.set_control("paused", "1" if paused else "0", by)

    def is_paused(self) -> bool:
        return self.get_control("paused", "0") == "1"

    # ---- approvals ----

    def create_approval(self, tool: str, arguments: dict,
                        reason: Optional[str] = None,
                        risk_score: Optional[int] = None) -> int:
        args_text = json.dumps(arguments, separators=(",", ":"),
                               ensure_ascii=False, sort_keys=True)
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO approvals (ts, tool, arguments, reason, risk_score)"
                " VALUES (?,?,?,?,?)",
                (time.time(), tool, args_text, reason, risk_score),
            )
            return int(cur.lastrowid)

    def approval_status(self, approval_id: int) -> Optional[str]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT status FROM approvals WHERE id=?", (approval_id,)).fetchone()
        return row["status"] if row else None

    def decide_approval(self, approval_id: int, status: str,
                        decided_by: str = "cli") -> bool:
        if status not in ("approved", "denied", "expired"):
            raise ValueError(f"invalid approval status: {status}")
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "UPDATE approvals SET status=?, decided_ts=?, decided_by=?"
                " WHERE id=? AND status='pending'",
                (status, time.time(), decided_by, approval_id),
            )
            return cur.rowcount == 1

    def pending_approvals(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM approvals WHERE status='pending' ORDER BY id").fetchall()
        return [dict(r) for r in rows]
