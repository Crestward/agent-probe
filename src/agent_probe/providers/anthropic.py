"""Anthropic provider — translates the neutral conversation to the Messages API
and back, driving one turn per `generate` call.

Notes (from the claude-api skill):
- Default model is claude-opus-5-5; thinking is always on, so we omit the
  `thinking` param. Returned content (incl. thinking blocks) is echoed back
  verbatim via Msg.raw to keep multi-turn tool use valid.
- tool_choice is left at the default (auto); forced tool use is rejected on
  current models anyway.
- Tool inputs arrive already parsed as dicts.
"""

from __future__ import annotations

from typing import Any

import anthropic

from agent_probe.models import Completion, Msg, ToolCall, ToolSpec

DEFAULT_MAX_TOKENS = 8192


class AnthropicProvider:
    name = "anthropic"

    def __init__(
        self,
        api_key: str,
        model: str,
        system: str | None = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> None:
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model
        self.system = system
        self.max_tokens = max_tokens

    def generate(self, messages: list[Msg], tools: list[ToolSpec]) -> Completion:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [self._to_native(m) for m in messages],
        }
        if self.system:
            kwargs["system"] = self.system
        if tools:
            kwargs["tools"] = [
                {"name": t.name, "description": t.description, "input_schema": t.input_schema}
                for t in tools
            ]

        resp = self.client.messages.create(**kwargs)

        text = "".join(b.text for b in resp.content if b.type == "text")
        tool_calls = [
            ToolCall(id=b.id, name=b.name, arguments=dict(b.input))
            for b in resp.content
            if b.type == "tool_use"
        ]
        return Completion(
            text=text,
            tool_calls=tool_calls,
            stop_reason=resp.stop_reason or "",
            raw=resp.content,
            input_tokens=resp.usage.input_tokens,
            output_tokens=resp.usage.output_tokens,
        )

    @staticmethod
    def _to_native(m: Msg) -> dict[str, Any]:
        if m.role == "assistant":
            # Echo the native content list back unchanged (preserves thinking/tool blocks).
            return {"role": "assistant", "content": m.raw}
        if m.role == "tool_results":
            return {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": tid, "content": out}
                    for tid, out in (m.tool_results or [])
                ],
            }
        return {"role": "user", "content": m.text or ""}
