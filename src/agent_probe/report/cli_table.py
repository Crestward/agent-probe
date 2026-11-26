"""Render a run to the terminal: a per-probe table + a metrics summary.

This is the surface you screen-record for the Phase 1 demo GIF.
"""

from __future__ import annotations

from collections.abc import Sequence

from rich.console import Console
from rich.table import Table

from agent_probe.models import Metrics, Outcome, ProbeResult

_OUTCOME_STYLE = {
    Outcome.SUCCESS: "[bold red]SUCCESS[/]",
    Outcome.REFUSAL: "[green]refusal[/]",
    Outcome.CLEAN_COMPLETION: "[cyan]clean[/]",
    Outcome.ERROR: "[yellow]error[/]",
}


def render(
    metrics: Metrics,
    results: Sequence[ProbeResult],
    provider: str,
    model: str,
    console: Console | None = None,
) -> None:
    console = console or Console()
    console.print(
        f"\n[bold]agent-probe[/]  ·  provider=[cyan]{provider}[/]  model=[cyan]{model}[/]\n"
    )

    probes = Table(title="Probes", title_justify="left", header_style="bold")
    probes.add_column("attack")
    probes.add_column("OWASP")
    probes.add_column("family")
    probes.add_column("outcome")
    probes.add_column("hijack", justify="center")
    probes.add_column("ms", justify="right")
    for r in results:
        probes.add_row(
            r.attack_id,
            r.owasp,
            r.family,
            _OUTCOME_STYLE.get(r.outcome, r.outcome.value),
            "✗" if r.tool_hijack else "·",
            str(r.latency_ms),
        )
    console.print(probes)

    summary = Table(title="Metrics", title_justify="left", header_style="bold")
    summary.add_column("metric")
    summary.add_column("value", justify="right")
    summary.add_row("[bold red]ASR[/] (attack success rate)", _pct(metrics.asr))
    summary.add_row("RR (refusal rate)", _pct(metrics.rr))
    summary.add_row("Clean-completion rate", _pct(metrics.clean_completion_rate))
    summary.add_row("Tool-hijack rate", _pct(metrics.tool_hijack_rate))
    summary.add_row("scored / total", f"{metrics.n_scored} / {metrics.n_total}")
    if metrics.n_error:
        summary.add_row("[yellow]errors (excluded)[/]", str(metrics.n_error))
    console.print(summary)


def _pct(x: float) -> str:
    return f"{x * 100:.1f}%"
