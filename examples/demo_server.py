#!/usr/bin/env python3
"""A tiny stdio MCP server used for demos and tests.

Simulates a dangerous-but-typical internal toolset: doc search (leaks PII),
email, money transfer, file deletion. Stdlib only.
"""
import json
import sys

TOOLS = [
    {"name": "search_docs",
     "description": "Search internal documents",
     "inputSchema": {"type": "object",
                     "properties": {"query": {"type": "string"}},
                     "required": ["query"]}},
    {"name": "send_email",
     "description": "Send an email",
     "inputSchema": {"type": "object",
                     "properties": {"to": {"type": "string"},
                                    "subject": {"type": "string"},
                                    "body": {"type": "string"}},
                     "required": ["to", "subject", "body"]}},
    {"name": "transfer_money",
     "description": "Transfer money to a recipient",
     "inputSchema": {"type": "object",
                     "properties": {"amount": {"type": "number"},
                                    "recipient": {"type": "string"}},
                     "required": ["amount", "recipient"]}},
    {"name": "delete_file",
     "description": "Delete a file by path",
     "inputSchema": {"type": "object",
                     "properties": {"path": {"type": "string"}},
                     "required": ["path"]}},
]


def text_result(text):
    return {"content": [{"type": "text", "text": text}], "isError": False}


def call_tool(name, args):
    if name == "search_docs":
        return text_result(
            f"Found 2 documents for '{args['query']}'. "
            "Owner: jane.doe@acme-corp.com. "
            "Staging credentials: sk-test-a1b2c3d4e5f6g7h8i9j0k1.")
    if name == "send_email":
        return text_result(f"Email sent to {args['to']}: '{args['subject']}'")
    if name == "transfer_money":
        return text_result(f"Transferred ${args['amount']} to {args['recipient']}")
    if name == "delete_file":
        return text_result(f"Deleted {args['path']}")
    raise ValueError(f"unknown tool: {name}")


def main():
    out = sys.stdout
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = msg.get("method")
        req_id = msg.get("id")
        if method is None or method.startswith("notifications/"):
            continue
        if method == "initialize":
            result = {"protocolVersion": msg.get("params", {}).get(
                          "protocolVersion", "2025-06-18"),
                      "capabilities": {"tools": {}},
                      "serverInfo": {"name": "demo-server", "version": "1.0"}}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            params = msg.get("params", {})
            try:
                result = call_tool(params.get("name"),
                                   params.get("arguments", {}))
            except Exception as exc:
                result = {"content": [{"type": "text", "text": str(exc)}],
                          "isError": True}
        else:
            out.write(json.dumps({"jsonrpc": "2.0", "id": req_id,
                                  "error": {"code": -32601,
                                            "message": "method not found"}}) + "\n")
            out.flush()
            continue
        out.write(json.dumps({"jsonrpc": "2.0", "id": req_id,
                              "result": result}) + "\n")
        out.flush()


if __name__ == "__main__":
    main()
