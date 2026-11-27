"""Provider registry — the target model is a first-class, pluggable knob.

Built-in names:
  anthropic          Claude (ANTHROPIC_API_KEY), any --model
  openai             OpenAI chat-completions (OPENAI_API_KEY), any --model
  deepseek           DeepSeek (DEEPSEEK_API_KEY), OpenAI-compatible
  local              Ollama on localhost (no key) — free, offline
  openai-compatible  BRING YOUR OWN: any OpenAI-compatible endpoint via --base-url
                     (+ --model, optional CUSTOM_API_KEY). vLLM, LM Studio, Together,
                     Groq, a self-hosted model — if it speaks chat-completions, you
                     can red-team it.
"""

from __future__ import annotations

from agent_probe.config import Settings
from agent_probe.providers.anthropic import AnthropicProvider
from agent_probe.providers.base import Provider
from agent_probe.providers.openai_compatible import OpenAICompatibleProvider

__all__ = ["Provider", "AnthropicProvider", "OpenAICompatibleProvider", "get_provider"]

PROVIDERS = ("anthropic", "openai", "deepseek", "local", "openai-compatible")


def get_provider(
    name: str,
    settings: Settings,
    system: str | None = None,
    model: str | None = None,
    base_url: str | None = None,
) -> Provider:
    if name == "anthropic":
        return AnthropicProvider(
            api_key=settings.require_key_for("anthropic"),
            model=model or settings.anthropic_model,
            system=system,
        )
    if name == "openai":
        return OpenAICompatibleProvider(
            name="openai",
            model=model or settings.openai_model,
            api_key=settings.require_key_for("openai"),
            base_url=settings.openai_base_url,
            system=system,
        )
    if name == "deepseek":
        return OpenAICompatibleProvider(
            name="deepseek",
            model=model or settings.deepseek_model,
            api_key=settings.require_key_for("deepseek"),
            base_url=settings.deepseek_base_url,
            system=system,
        )
    if name == "local":
        # Ollama's OpenAI-compatible endpoint: free, offline, no ToS/ban risk.
        return OpenAICompatibleProvider(
            name="local",
            model=model or settings.local_model,
            api_key="ollama",
            base_url=settings.local_base_url,
            system=system,
        )
    if name == "openai-compatible":
        url = base_url or settings.custom_base_url
        chosen_model = model or settings.custom_model
        if not url:
            raise ValueError(
                "provider 'openai-compatible' needs an endpoint: pass --base-url "
                "<url> (or set AGENT_PROBE_CUSTOM_BASE_URL)."
            )
        if not chosen_model:
            raise ValueError(
                "provider 'openai-compatible' needs a model: pass --model <name> "
                "(or set AGENT_PROBE_CUSTOM_MODEL)."
            )
        return OpenAICompatibleProvider(
            name="openai-compatible",
            model=chosen_model,
            # Many local servers accept any token; a real key goes in CUSTOM_API_KEY.
            api_key=settings.custom_api_key or "not-needed",
            base_url=url,
            system=system,
        )
    raise ValueError(f"unknown provider '{name}'. Options: {', '.join(PROVIDERS)}.")
