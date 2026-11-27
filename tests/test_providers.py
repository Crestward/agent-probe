"""Provider registry: the bring-your-own-model path and clear errors."""

from __future__ import annotations

import pytest

from agent_probe.config import Settings
from agent_probe.providers import get_provider
from agent_probe.providers.openai_compatible import OpenAICompatibleProvider


def _settings() -> Settings:
    return Settings(_env_file=None)


def test_openai_compatible_requires_base_url() -> None:
    with pytest.raises(ValueError, match="base-url"):
        get_provider("openai-compatible", _settings(), model="m")


def test_openai_compatible_requires_model() -> None:
    with pytest.raises(ValueError, match="model"):
        get_provider("openai-compatible", _settings(), base_url="http://x/v1")


def test_openai_compatible_builds_with_endpoint() -> None:
    p = get_provider(
        "openai-compatible", _settings(), model="my-model", base_url="http://x/v1"
    )
    assert isinstance(p, OpenAICompatibleProvider)
    assert p.model == "my-model"
    assert p.name == "openai-compatible"


def test_local_needs_no_key() -> None:
    p = get_provider("local", _settings(), model="qwen")
    assert isinstance(p, OpenAICompatibleProvider)
    assert p.name == "local"


def test_unknown_provider_lists_options() -> None:
    with pytest.raises(ValueError, match="openai-compatible"):
        get_provider("nope", _settings())
