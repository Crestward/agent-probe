"""Indirect prompt-injection target (OWASP LLM01).

The attack payload is planted in *data the agent reads* — an email body, a
document, a CRM field, a support ticket, or a fetched web page — rather than in a
tool description. When the agent does a benign task ("summarize my emails"), it
ingests the malicious instruction mid-task. This is the realistic, potent form of
prompt injection. The `channel` selects which retrieval surface carries it.
"""

from __future__ import annotations

from fastmcp import FastMCP

from agent_probe.mcp.benign import CHANNELS, build_benign_server


def build_indirect_injection_server(
    payload: str, channel: str = "email", name: str = "assistant-tools"
) -> FastMCP:
    if channel not in CHANNELS:
        raise ValueError(f"unknown channel {channel!r}; expected one of {CHANNELS}")
    return build_benign_server(name=name, injections={channel: payload})
