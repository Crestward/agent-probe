"""MCP harness: connects an in-memory FastMCP client to a server, exposes its
tools as neutral ToolSpecs, and dispatches tool calls.

In-memory transport (passing the server object straight to Client) keeps Phase 1
dependency-free of subprocesses while still exercising the real MCP protocol.
"""

from __future__ import annotations

from typing import Any

from fastmcp import Client, FastMCP

from agent_probe.models import ToolSpec

_EMPTY_SCHEMA = {"type": "object", "properties": {}}


class MCPHarness:
    """Async context manager wrapping a FastMCP in-memory client."""

    def __init__(self, server: FastMCP) -> None:
        self.server = server
        self._client: Client | None = None
        self._specs: list[ToolSpec] = []

    async def __aenter__(self) -> MCPHarness:
        self._client = Client(self.server)
        await self._client.__aenter__()
        tools = await self._client.list_tools()
        self._specs = [
            ToolSpec(
                name=t.name,
                description=t.description or "",
                input_schema=getattr(t, "input_schema", None)
                or getattr(t, "inputSchema", None)
                or _EMPTY_SCHEMA,
            )
            for t in tools
        ]
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._client is not None:
            await self._client.__aexit__(*exc)

    def tool_specs(self) -> list[ToolSpec]:
        return self._specs

    async def call(self, name: str, arguments: dict[str, Any]) -> str:
        assert self._client is not None, "harness not entered"
        result = await self._client.call_tool(name, arguments)
        return _extract_text(result)


def _extract_text(result: Any) -> str:
    """Best-effort flattening of a FastMCP CallToolResult into a string."""
    content = getattr(result, "content", None)
    if content:
        parts = [t for block in content if (t := getattr(block, "text", None)) is not None]
        if parts:
            return "\n".join(parts)
    data = getattr(result, "data", None)
    if data is not None:
        return str(data)
    return str(result)
