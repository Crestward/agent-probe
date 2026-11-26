"""Typed settings loaded from the environment / a local `.env` file.

Only the default provider's API key is required; the others are validated lazily
(when that provider is actually selected) via `require_key_for`.
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Provider -> the env var holding its API key.
PROVIDER_KEY_ENV: dict[str, str] = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "local": "",  # no key needed
}

# DeepSeek speaks the OpenAI API with a different base URL.
DEEPSEEK_BASE_URL = "https://api.deepseek.com"


class Settings(BaseSettings):
    """Runtime configuration. Prefix env vars with AGENT_PROBE_ unless noted."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="AGENT_PROBE_",
        extra="ignore",
    )

    # --- API keys (NOT prefixed — standard SDK names) --------------------------
    anthropic_api_key: str = Field(default="", alias="ANTHROPIC_API_KEY")
    openai_api_key: str = Field(default="", alias="OPENAI_API_KEY")
    deepseek_api_key: str = Field(default="", alias="DEEPSEEK_API_KEY")

    # --- Behaviour (AGENT_PROBE_ prefixed) -------------------------------------
    default_provider: str = "anthropic"
    # Default target model for the agent-under-test. claude-opus-5-5 is the current
    # flagship; for high-volume probe runs set AGENT_PROBE_ANTHROPIC_MODEL to a cheaper
    # model (e.g. claude-sonnet-5-5 / claude-haiku-4-5).
    anthropic_model: str = "claude-opus-5-5"
    openai_model: str = "gpt-4.1"
    deepseek_model: str = "deepseek-chat"
    # Local target via Ollama's OpenAI-compatible endpoint (free, offline, no ToS risk).
    local_model: str = "qwen2.5:7b-instruct-q4_K_M"
    local_base_url: str = "http://localhost:11434/v1"
    log_level: str = "INFO"

    def key_for(self, provider: str) -> str:
        return {
            "anthropic": self.anthropic_api_key,
            "openai": self.openai_api_key,
            "deepseek": self.deepseek_api_key,
            "local": "",
        }.get(provider, "")

    def require_key_for(self, provider: str) -> str:
        """Return the key for `provider`, raising a clear error if it is missing."""
        if provider == "local":
            return ""
        key = self.key_for(provider)
        if not key:
            env = PROVIDER_KEY_ENV.get(provider, "?")
            raise RuntimeError(
                f"No API key for provider '{provider}'. "
                f"Set {env} in your environment or .env file (see .env.example)."
            )
        return key


def load_settings() -> Settings:
    """Load settings. Separated so tests can monkeypatch the environment."""
    return Settings()
