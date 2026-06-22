"""Newline-delimited JSON-RPC 2.0 framing (MCP stdio transport)."""
from __future__ import annotations

import json
from typing import Any, Optional, TextIO

PARSE_ERROR = -32700
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


def write_message(stream: TextIO, msg: dict) -> None:
    stream.write(json.dumps(msg, separators=(",", ":"), ensure_ascii=False) + "\n")
    stream.flush()


# Cap one newline-delimited frame. GRIT's threat model includes a compromised
# upstream; an unbounded readline() would let one emit a multi-GB line with no
# newline and OOM the gateway. readline(max_bytes) reads at most this many chars
# per call, so an oversized frame is consumed in bounded chunks that each fail
# to parse and are skipped — generous enough that real MCP payloads (large file
# or image results) are never split.
MAX_MESSAGE_BYTES = 64 * 1024 * 1024


def read_message(stream: TextIO,
                 max_bytes: int = MAX_MESSAGE_BYTES) -> Optional[dict]:
    """Read next JSON message. Returns None on EOF; skips blank/garbage lines
    and any single frame larger than max_bytes (bounded-memory framing)."""
    while True:
        line = stream.readline(max_bytes)
        if not line:
            return None
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(msg, dict):
            return msg


def response(req_id: Any, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def error_response(req_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def request(req_id: Any, method: str, params: dict) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}


def notification(method: str, params: Optional[dict] = None) -> dict:
    msg: dict = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    return msg
