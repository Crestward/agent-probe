"""Provider registry.

Phase 1 ships the Anthropic provider; OpenAI and DeepSeek land in Phase 3.
"""

from __future__ import annotations

from agent_probe.config import Settings
from agent_probe.providers.anthropic import AnthropicProvider
from agent_probe.providers.base import Provider

__all__ = ["Provider", "AnthropicProvider", "get_provider"]

_PHASE_3 = {"openai", "deepseek"}


def get_provider(name: str, settings: Settings, system: str | None = None) -> Provider:
    if name == "anthropic":
        return AnthropicProvider(
            api_key=settings.require_key_for("anthropic"),
            model=settings.anthropic_model,
            system=system,
        )
    if name in _PHASE_3:
        raise ValueError(f"provider '{name}' is not wired yet — lands in Phase 3 (see tasks.md).")
    raise ValueError(f"unknown provider '{name}'. Options: anthropic (openai/deepseek in Phase 3).")
