"""Test helpers: a scripted provider that replays a fixed list of Completions."""

from __future__ import annotations

from agent_probe.models import Completion, Msg, ToolSpec


class FakeProvider:
    """Returns queued Completions in order, one per generate() call."""

    name = "fake"

    def __init__(self, script: list[Completion], model: str = "fake-1") -> None:
        self.model = model
        self._script = list(script)
        self._i = 0
        self.calls: list[tuple[list[Msg], list[ToolSpec]]] = []

    def generate(self, messages: list[Msg], tools: list[ToolSpec]) -> Completion:
        self.calls.append((messages, tools))
        step = self._script[self._i]
        self._i += 1
        return step
