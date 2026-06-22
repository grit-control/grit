"""Manage upstream MCP servers (stdio subprocesses)."""
from __future__ import annotations

import itertools
import json
import os
import queue
import subprocess
import threading
from typing import Optional

from . import __version__
from .jsonrpc import MAX_MESSAGE_BYTES, notification, request

PROTOCOL_VERSION = "2025-06-18"


class UpstreamError(Exception):
    pass


class UpstreamServer:
    def __init__(self, name: str, command: str, args: Optional[list[str]] = None,
                 env: Optional[dict[str, str]] = None, timeout: float = 30.0):
        self.name = name
        self.command = command
        self.args = args or []
        self.extra_env = env or {}
        self.timeout = timeout
        self.proc: Optional[subprocess.Popen] = None
        self.tools: list[dict] = []
        self._ids = itertools.count(1)
        self._lock = threading.Lock()
        self._queue: queue.Queue = queue.Queue()

    def start(self) -> list[dict]:
        env = dict(os.environ)
        env.update(self.extra_env)
        self.proc = subprocess.Popen(
            [self.command, *self.args],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, encoding="utf-8",
            env=env, bufsize=1,
        )
        threading.Thread(target=self._reader, daemon=True).start()
        self.request("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "grit", "version": __version__},
        })
        self._send(notification("notifications/initialized"))
        self.tools = self.request("tools/list", {}).get("tools", [])
        return self.tools

    def call_tool(self, name: str, arguments: dict) -> dict:
        return self.request("tools/call", {"name": name, "arguments": arguments})

    def request(self, method: str, params: dict) -> dict:
        with self._lock:
            req_id = next(self._ids)
            self._send(request(req_id, method, params))
            while True:
                try:
                    msg = self._queue.get(timeout=self.timeout)
                except queue.Empty:
                    raise UpstreamError(
                        f"upstream '{self.name}' timed out on {method}") from None
                if msg is None:
                    raise UpstreamError(f"upstream '{self.name}' exited unexpectedly")
                if msg.get("id") != req_id:
                    continue  # notification or stale message
                if "error" in msg:
                    err = msg["error"]
                    raise UpstreamError(
                        f"upstream '{self.name}' error {err.get('code')}: "
                        f"{err.get('message')}")
                return msg.get("result", {})

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def _send(self, msg: dict) -> None:
        if not self.proc or not self.proc.stdin:
            raise UpstreamError(f"upstream '{self.name}' is not running")
        try:
            self.proc.stdin.write(
                json.dumps(msg, separators=(",", ":"), ensure_ascii=False) + "\n")
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise UpstreamError(f"upstream '{self.name}' pipe broken: {exc}") from exc

    def _reader(self) -> None:
        assert self.proc and self.proc.stdout
        # bounded readline: a compromised upstream must not OOM us with one
        # giant newline-less frame (see jsonrpc.MAX_MESSAGE_BYTES).
        while True:
            line = self.proc.stdout.readline(MAX_MESSAGE_BYTES)
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                self._queue.put(json.loads(line))
            except json.JSONDecodeError:
                continue
        self._queue.put(None)
