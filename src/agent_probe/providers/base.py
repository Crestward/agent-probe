"""Provider protocol — one interface across Anthropic / OpenAI / DeepSeek."""

from __future__ import annotations

from typing import Protocol

from agent_probe.models import Completion, Msg, ToolSpec


class Provider(Protocol):
    name: str
    model: str

    def generate(self, messages: list[Msg], tools: list[ToolSpec]) -> Completion:
        """Run one model turn: given the conversation + available tools, return
        the assistant's text and any tool calls it wants to make."""
        ...
