"""agent-probe command-line interface.

Phase 0: the command surface exists and `--help` works end-to-end. The
subcommands are wired as stubs and raise a clear "not implemented yet" notice
pointing at the phase that lands them (see tasks.md).
"""

from __future__ import annotations

import typer
from rich.console import Console

from agent_probe import __version__
from agent_probe.config import load_settings
from agent_probe.logging import setup_logging

app = typer.Typer(
    name="agent-probe",
    help="Attack LLM agents & their MCP tools, then measure the defence "
    "(ASR / Refusal Rate / tool-hijack rate). See SPEC.md.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()

# Phase that will implement each command — keeps the roadmap visible in the tool.
_NOT_YET = "[yellow]not implemented yet[/] — lands in {phase} (see tasks.md)."


def _stub(command: str, phase: str) -> None:
    console.print(f"[bold]agent-probe {command}[/]: " + _NOT_YET.format(phase=phase))
    raise typer.Exit(code=0)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"agent-probe {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    _version: bool = typer.Option(
        None, "--version", callback=_version_callback, is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """agent-probe — MCP/agent red-teaming & guardrail benchmark."""
    setup_logging(load_settings().log_level)


@app.command()
def run(
    suite: str = typer.Argument(..., help="Path to an eval suite YAML (e.g. evals/gold.yaml)."),
    provider: str = typer.Option("anthropic", help="anthropic | openai | deepseek | local."),
    compare: str = typer.Option(
        None, help="Comma-separated providers to run the same suite against, e.g. "
        "anthropic,openai,deepseek.",
    ),
) -> None:
    """Run an attack suite against a target agent and score it."""
    _stub("run", "Phase 1 (single provider) / Phase 3 (--compare)")


@app.command()
def report(
    results: str = typer.Argument(..., help="Path to a results JSONL file."),
    format: str = typer.Option("md", help="md | json."),
) -> None:
    """Render a results table (Markdown for the README, or JSON)."""
    _stub("report", "Phase 2")


@app.command()
def gate(
    results: str = typer.Argument(..., help="Path to the GUARDED-config results JSONL."),
    max_asr: float = typer.Option(
        ..., "--max-asr", help="Fail (exit 1) if guarded ASR exceeds this."
    ),
) -> None:
    """CI gate: exit non-zero if the guarded-config ASR regresses past --max-asr."""
    _stub("gate", "Phase 4")


@app.command("list")
def list_attacks(
    owasp: str = typer.Option(None, help="Filter by OWASP id, e.g. LLM03."),
) -> None:
    """Browse the attack catalog."""
    _stub("list", "Phase 2")


if __name__ == "__main__":
    app()
