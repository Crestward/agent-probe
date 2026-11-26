"""OpenAI-compatible provider — drives any chat-completions endpoint.

Used now for the local Ollama target, and reused in Phase 3 for OpenAI and
DeepSeek (both speak this same API, differing only in base_url + key + model).

Translation vs. the neutral model:
- tools  -> {"type": "function", "function": {name, description, parameters}}
- assistant turns are echoed back via Msg.raw (a reconstructed message dict)
- each tool result becomes its own {"role": "tool", ...} message
- finish_reason is mapped to our stop_reason vocabulary
"""

from __future__ import annotations

import json
from typing import Any

from openai import OpenAI

from agent_probe.models import Completion, Msg, ToolCall, ToolSpec

DEFAULT_MAX_TOKENS = 2048

_FINISH_TO_STOP = {
    "tool_calls": "tool_use",
    "stop": "end_turn",
    "length": "max_tokens",
    "content_filter": "refusal",
}


class OpenAICompatibleProvider:
    def __init__(
        self,
        name: str,
        model: str,
        api_key: str,
        base_url: str | None = None,
        system: str | None = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> None:
        self.name = name
        self.model = model
        self.system = system
        self.max_tokens = max_tokens
        self.client = OpenAI(api_key=api_key or "not-needed", base_url=base_url)

    def generate(self, messages: list[Msg], tools: list[ToolSpec]) -> Completion:
        native: list[dict[str, Any]] = []
        if self.system:
            native.append({"role": "system", "content": self.system})
        for m in messages:
            native.extend(self._to_native(m))

        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": native,
        }
        if tools:
            kwargs["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.input_schema,
                    },
                }
                for t in tools
            ]
            kwargs["tool_choice"] = "auto"

        resp = self.client.chat.completions.create(**kwargs)
        choice = resp.choices[0]
        msg = choice.message

        tool_calls = [
            ToolCall(id=tc.id, name=tc.function.name, arguments=_parse_args(tc.function.arguments))
            for tc in (msg.tool_calls or [])
        ]
        usage = resp.usage
        return Completion(
            text=msg.content or "",
            tool_calls=tool_calls,
            stop_reason=_FINISH_TO_STOP.get(choice.finish_reason or "", choice.finish_reason or ""),
            raw=_assistant_echo(msg),
            input_tokens=getattr(usage, "prompt_tokens", 0) or 0,
            output_tokens=getattr(usage, "completion_tokens", 0) or 0,
        )

    @staticmethod
    def _to_native(m: Msg) -> list[dict[str, Any]]:
        if m.role == "assistant":
            return [m.raw]
        if m.role == "tool_results":
            return [
                {"role": "tool", "tool_call_id": tid, "content": out}
                for tid, out in (m.tool_results or [])
            ]
        return [{"role": "user", "content": m.text or ""}]


def _parse_args(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {}


def _assistant_echo(msg: Any) -> dict[str, Any]:
    """Rebuild a minimal assistant message dict to send back on the next turn."""
    echo: dict[str, Any] = {"role": "assistant", "content": msg.content or ""}
    if msg.tool_calls:
        echo["tool_calls"] = [
            {
                "id": tc.id,
                "type": "function",
                "function": {"name": tc.function.name, "arguments": tc.function.arguments},
            }
            for tc in msg.tool_calls
        ]
    return echo
