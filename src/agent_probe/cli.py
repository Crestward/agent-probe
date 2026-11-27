"""agent-probe command-line interface.

Phase 0: the command surface exists and `--help` works end-to-end. The
subcommands are wired as stubs and raise a clear "not implemented yet" notice
pointing at the phase that lands them (see tasks.md).
"""

from __future__ import annotations

import contextlib
import sys

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


def _force_utf8_stdio() -> None:
    """Windows consoles default to cp1252 and crash on non-ASCII output; make
    stdout/stderr UTF-8 with replacement so results never fail to render."""
    for stream in ("stdout", "stderr"):
        s = getattr(sys, stream, None)
        if s is not None and hasattr(s, "reconfigure"):
            with contextlib.suppress(ValueError, OSError):
                s.reconfigure(encoding="utf-8", errors="replace")


@app.callback()
def main(
    _version: bool = typer.Option(
        None, "--version", callback=_version_callback, is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """agent-probe — MCP/agent red-teaming & guardrail benchmark."""
    _force_utf8_stdio()
    setup_logging(load_settings().log_level)


@app.command()
def run(
    suite: str = typer.Argument(..., help="Path to an eval suite YAML (e.g. evals/smoke.yaml)."),
    provider: str = typer.Option("anthropic", help="anthropic | openai | deepseek | local."),
    model: str = typer.Option(
        None,
        "--model",
        help="Override the target model, e.g. claude-haiku-4-5 / claude-sonnet-5-5.",
    ),
    compare: str = typer.Option(
        None, help="Comma-separated providers to run the same suite against, e.g. "
        "anthropic,openai,deepseek.",
    ),
    guard: bool = typer.Option(
        False, "--guard", help="Enable the I/O guardrail (the GUARDED config for the Delta)."
    ),
) -> None:
    """Run an attack suite against a target agent and score it."""
    import asyncio
    from pathlib import Path

    from agent_probe.agent.loop import DEFAULT_SYSTEM
    from agent_probe.logging import new_run_id
    from agent_probe.orchestrator import run_suite
    from agent_probe.providers import get_provider
    from agent_probe.report.cli_table import render
    from agent_probe.scoring import score
    from agent_probe.store import write_results

    if compare:
        console.print("[yellow]--compare[/] lands in Phase 3 — run a single --provider for now.")
        raise typer.Exit(code=0)

    settings = load_settings()
    run_id = new_run_id()

    def make_provider(system: str = DEFAULT_SYSTEM):
        return get_provider(provider, settings, system=system, model=model)

    try:
        results = asyncio.run(run_suite(suite, make_provider, run_id, guarded=guard))
    except ValueError as e:  # unknown/unwired provider
        console.print(f"[red]error:[/] {e}")
        raise typer.Exit(code=2) from e
    except RuntimeError as e:  # missing API key
        console.print(f"[red]error:[/] {e}")
        raise typer.Exit(code=2) from e

    metrics = score(results)
    out_path = Path("evals/results") / f"{run_id}.jsonl"
    write_results(out_path, results)
    from agent_probe.store import write_sqlite

    db_path = Path("evals/results") / "probes.db"
    write_sqlite(db_path, results)

    model = results[0].model if results else "?"
    render(metrics, results, provider, model, console=console)
    cfg = "guarded" if guard else "baseline"
    console.print(
        f"\nconfig=[cyan]{cfg}[/]  ·  results written to [cyan]{out_path}[/]  ·  "
        f"sqlite [cyan]{db_path}[/]  (run_id={run_id})"
    )


@app.command()
def report(
    results: str = typer.Argument(..., help="Path to a results JSONL file."),
    format: str = typer.Option("md", help="md | json."),
) -> None:
    """Render a results table (Markdown for the README, or JSON)."""
    from agent_probe.report.markdown import render_markdown
    from agent_probe.scoring import score
    from agent_probe.store import read_results

    rows = read_results(results)
    if format == "json":
        console.print_json(score(rows).model_dump_json())
    else:
        # print() not print_json: Rich must not reinterpret the Markdown markup.
        print(render_markdown(rows))


@app.command()
def delta(
    baseline: str = typer.Argument(..., help="Baseline (undefended) results JSONL."),
    guarded: str = typer.Argument(..., help="Guarded (guardrail-on) results JSONL."),
) -> None:
    """Defence Delta: ASR before vs after the guardrail, overall and per family."""
    from agent_probe.report.markdown import render_delta
    from agent_probe.store import read_results

    print(render_delta(read_results(baseline), read_results(guarded)))


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
    family: str = typer.Option(None, help="Filter by family, e.g. mcp_tool_shadowing."),
    directory: str = typer.Option("attacks/gold", help="Catalog directory to browse."),
) -> None:
    """Browse the attack catalog."""
    from rich.table import Table

    from agent_probe.attacks.spec import load_catalog

    attacks = load_catalog(directory, owasp=owasp, family=family)
    table = Table(title=f"Attack catalog ({len(attacks)})", title_justify="left",
                  header_style="bold")
    for col in ("id", "family", "OWASP", "ATLAS", "channel", "sev", "technique"):
        table.add_column(col)
    for a in attacks:
        table.add_row(
            a.id, a.family, a.owasp, a.atlas or "-", a.channel, a.severity,
            a.technique or "-",
        )
    console.print(table)


if __name__ == "__main__":
    app()
