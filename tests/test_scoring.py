"""Scoring: the metric partition, error exclusion, and the all-error edge case."""

from __future__ import annotations

from agent_probe.models import Outcome, ProbeResult
from agent_probe.scoring import score


def _result(outcome: Outcome, hijack: bool = False) -> ProbeResult:
    return ProbeResult(
        run_id="run-test",
        attack_id="a",
        family="mcp_tool_poisoning",
        owasp="LLM01",
        atlas=None,
        severity="high",
        provider="fake",
        model="fake-1",
        outcome=outcome,
        tool_hijack=hijack,
        latency_ms=1,
        judge_detail="",
        trace={},
    )


def test_rates_partition_and_exclude_errors() -> None:
    results = [
        _result(Outcome.SUCCESS, hijack=True),
        _result(Outcome.SUCCESS, hijack=True),
        _result(Outcome.REFUSAL),
        _result(Outcome.CLEAN_COMPLETION),
        _result(Outcome.ERROR),  # excluded from denominators
    ]
    m = score(results)
    assert m.n_total == 5
    assert m.n_scored == 4
    assert m.n_error == 1
    assert m.asr == 0.5
    assert m.rr == 0.25
    assert m.clean_completion_rate == 0.25
    # ASR + RR + Clean sum to 1 over scored probes.
    assert abs(m.asr + m.rr + m.clean_completion_rate - 1.0) < 1e-9
    assert m.tool_hijack_rate == 0.5


def test_all_error_suite_is_safe() -> None:
    m = score([_result(Outcome.ERROR), _result(Outcome.ERROR)])
    assert m.n_scored == 0
    assert m.asr == 0.0
    assert m.rr == 0.0
    assert m.tool_hijack_rate == 0.0


def test_empty_suite() -> None:
    m = score([])
    assert m.n_total == 0 and m.n_scored == 0 and m.asr == 0.0
