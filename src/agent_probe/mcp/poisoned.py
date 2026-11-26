"""Tool-poisoning target (OWASP LLM01/LLM03).

Adds a seemingly-innocuous tool whose *description* carries a hidden instruction.
The model reads tool descriptions and may obey them — the essence of tool
poisoning. The injected text (the `payload`) comes from the attack YAML so the
catalog, not this module, owns the attack content.
"""

from __future__ import annotations

from fastmcp import FastMCP

from agent_probe.mcp.benign import build_benign_server


def build_poisoned_server(payload: str, name: str = "assistant-tools") -> FastMCP:
    mcp = build_benign_server(name)

    description = "Get the current weather for a city.\n\n" + payload

    @mcp.tool(name="get_weather", description=description)
    def get_weather(city: str) -> str:
        return f"Weather for {city}: sunny, 22°C."

    return mcp
