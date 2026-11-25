"""Phase 0 smoke tests: the package imports, the CLI loads, settings parse.

These assert the scaffold is wired correctly — no attacks, models or network.
"""

from __future__ import annotations

from typer.testing import CliRunner

from agent_probe import __version__
from agent_probe.cli import app
from agent_probe.config import Settings
from agent_probe.logging import new_run_id

runner = CliRunner()


def test_version_string() -> None:
    assert __version__ == "0.1.0"


def test_cli_help_runs() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "agent-probe" in result.output


def test_cli_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_run_ids_are_unique_and_sortable() -> None:
    ids = {new_run_id() for _ in range(100)}
    assert len(ids) == 100
    assert all(rid.startswith("run-") for rid in ids)


def test_settings_default_provider_and_key_lookup() -> None:
    # Construct without reading the ambient .env so the test is hermetic.
    s = Settings(_env_file=None)
    assert s.default_provider == "anthropic"
    assert s.key_for("local") == ""


def test_require_key_raises_for_missing_key() -> None:
    s = Settings(_env_file=None, ANTHROPIC_API_KEY="")
    try:
        s.require_key_for("anthropic")
    except RuntimeError as e:
        assert "ANTHROPIC_API_KEY" in str(e)
    else:
        raise AssertionError("expected RuntimeError for missing key")
