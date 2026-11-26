"""Render a results set as Markdown — the published README table (SPEC §8).

Headline metrics, then per-OWASP and per-family breakdowns. Pure string output so
it can be written straight into README.md or printed by `agent-probe report`.
"""

from __future__ import annotations

from collections.abc import Sequence

from agent_probe.models import GroupMetrics, Metrics, ProbeResult
from agent_probe.scoring import score, score_by_family, score_by_owasp


def _pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def _overall_table(m: Metrics) -> str:
    rows = [
        ("**ASR** (attack success rate)", _pct(m.asr)),
        ("Refusal rate", _pct(m.rr)),
        ("Clean-completion rate", _pct(m.clean_completion_rate)),
        ("Tool-hijack rate", _pct(m.tool_hijack_rate)),
        ("Harm-weighted ASR", _pct(m.harm_weighted_asr)),
        ("Scored / total", f"{m.n_scored} / {m.n_total}"),
    ]
    if m.n_error:
        rows.append(("Errors (excluded)", str(m.n_error)))
    body = "\n".join(f"| {k} | {v} |" for k, v in rows)
    return "| Metric | Value |\n|---|---|\n" + body


def _group_table(groups: Sequence[GroupMetrics], label: str) -> str:
    head = f"| {label} | n | ASR | RR | Hijack |\n|---|---:|---:|---:|---:|"
    rows = "\n".join(
        f"| {g.group} | {g.n_scored} | {_pct(g.asr)} | {_pct(g.rr)} | {_pct(g.tool_hijack_rate)} |"
        for g in groups
    )
    return head + "\n" + rows


def render_markdown(
    results: Sequence[ProbeResult],
    provider: str | None = None,
    model: str | None = None,
    title: str = "Results",
) -> str:
    m = score(results)
    provider = provider or (results[0].provider if results else "?")
    model = model or (results[0].model if results else "?")
    run_id = results[0].run_id if results else "?"

    parts = [
        f"## {title} — `{provider}` / `{model}`",
        "",
        f"_{m.n_total} probes · run `{run_id}`_",
        "",
        _overall_table(m),
        "",
        "### By OWASP LLM Top-10",
        "",
        _group_table(score_by_owasp(results), "OWASP"),
        "",
        "### By attack family",
        "",
        _group_table(score_by_family(results), "Family"),
        "",
    ]
    return "\n".join(parts)
