"""Indirect prompt-injection target (OWASP LLM01).

The attack payload is planted in *data the agent reads* — here, an email body
returned by `read_emails` — rather than in a tool description. When the agent
does a benign task ("summarize my emails"), it ingests the malicious instruction
mid-task. This is the realistic, potent form of prompt injection.
"""

from __future__ import annotations

from fastmcp import FastMCP

from agent_probe.mcp.benign import build_benign_server


def build_indirect_injection_server(payload: str, name: str = "assistant-tools") -> FastMCP:
    return build_benign_server(name=name, injected_email=payload)
