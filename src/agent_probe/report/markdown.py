"""Render a results set as Markdown — the published README table (SPEC §8).

Headline metrics, then per-OWASP and per-family breakdowns. Pure string output so
it can be written straight into README.md or printed by `agent-probe report`.
"""

from __future__ import annotations

from collections.abc import Sequence

from agent_probe.models import GroupMetrics, Metrics, ProbeResult
from agent_probe.scoring import defence_delta, score, score_by_family, score_by_owasp


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


def render_recommendations_md(recs) -> str:
    """The remediation report as Markdown — the measures to take."""
    if not recs:
        return "## Recommended actions\n\nNo successful attacks — no mitigations required.\n"
    parts = ["## Recommended actions", "",
             "_Prioritized measures to take, most urgent first._", ""]
    for r in recs:
        cover = "" if r.covered_by_guardrail else " — **not covered by the I/O guardrail**"
        parts.append(
            f"### `{r.priority.upper()}` · {r.family.replace('_', ' ')} "
            f"({r.owasp}, ASR {_pct(r.asr)}){cover}"
        )
        parts.append("")
        parts.append(f"_{r.finding}_")
        parts.append("")
        parts += [f"- {a}" for a in r.actions]
        parts.append("")
        parts.append(f"<sub>refs: {', '.join(r.refs)}</sub>")
        parts.append("")
    return "\n".join(parts)


def render_delta(
    baseline: Sequence[ProbeResult], guarded: Sequence[ProbeResult]
) -> str:
    """The Defence-Delta table: ASR baseline → guarded, with PR / ASR_f split."""
    rows = defence_delta(baseline, guarded)
    overall = rows[0]
    model = (guarded or baseline)[0].model if (guarded or baseline) else "?"

    head = (
        "| Group | n | ASR baseline | ASR guarded | Δ | Guard pass-rate | ASR behind filter |\n"
        "|---|---:|---:|---:|---:|---:|---:|"
    )
    body = "\n".join(
        f"| {r.group} | {r.n} | {_pct(r.asr_baseline)} | {_pct(r.asr_guarded)} | "
        f"**-{_pct(r.delta)}** | {_pct(r.guard_pass_rate)} | {_pct(r.asr_behind_filter)} |"
        for r in rows
    )
    return "\n".join(
        [
            f"## Defence Delta — `{model}` (I/O guardrail)",
            "",
            f"_Guardrail cut ASR from **{_pct(overall.asr_baseline)}** to "
            f"**{_pct(overall.asr_guarded)}** (**-{_pct(overall.delta)}**) on the same suite._",
            "",
            head,
            body,
            "",
        ]
    )


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
