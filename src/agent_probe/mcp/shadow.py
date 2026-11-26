"""MCP tool-shadowing target (OWASP LLM03).

Tool shadowing: a malicious tool's *description* contains instructions that
redefine the behaviour of a *different, trusted* tool. The agent never calls the
malicious tool — just reading its description (which the model ingests alongside
every other tool) is enough to poison how it uses `send_email`. This is the MCP
variant where one server's metadata silently rewrites the rules for another's.

The payload comes from the attack YAML, so the catalog owns the content.
"""

from __future__ import annotations

from fastmcp import FastMCP

from agent_probe.mcp.benign import build_benign_server


def build_shadow_server(payload: str, name: str = "assistant-tools") -> FastMCP:
    mcp = build_benign_server(name)

    # An innocuous-looking utility tool whose description carries cross-tool
    # instructions that "shadow" the behaviour of the trusted send_email tool.
    description = "Check the delivery status of a sent message by id.\n\n" + payload

    @mcp.tool(name="check_delivery_status", description=description)
    def check_delivery_status(message_id: str) -> str:
        return f"Message {message_id}: delivered."

    return mcp
