"""Run a suite: for each attack, stand up the target, run the agent, judge, score.

A suite YAML is minimal in Phase 1:

    name: smoke
    attacks:
      - attacks/gold/pi-tool-poison-001.yaml

`make_provider` is a zero-arg factory so each probe gets a fresh provider (and so
tests can inject a fake). Phase 3 adds multi-provider --compare here.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

import yaml

from agent_probe.agent.loop import DEFAULT_SYSTEM, Agent
from agent_probe.attacks.spec import load_attack
from agent_probe.guard.filter import IOFilter
from agent_probe.judge.rules import RuleJudge
from agent_probe.mcp.benign import CHANNELS, build_benign_server
from agent_probe.mcp.harness import MCPHarness
from agent_probe.mcp.indirect import build_indirect_injection_server
from agent_probe.mcp.poisoned import build_poisoned_server
from agent_probe.mcp.rugpull import build_rugpull_server
from agent_probe.mcp.shadow import build_shadow_server
from agent_probe.models import AttackSpec, ProbeResult
from agent_probe.providers.base import Provider

MAX_OUTPUT_CHARS = 500


def _build_server(attack: AttackSpec):
    """Pick the target server for an attack, keyed on family (+ channel).

    - MCP triad: poisoning (payload in a tool description), shadowing (payload
      redefines a trusted tool), rug-pull (tool mutates after approval).
    - Indirect injection: payload planted in the retrieval `channel`.
    - Everything else (excessive agency, sensitive-info disclosure, jailbreak
      carriers whose payload rides the task) runs against the plain benign server.
    """
    payload = attack.payload or ""
    if attack.family == "mcp_tool_poisoning":
        return build_poisoned_server(payload)
    if attack.family == "mcp_tool_shadowing":
        return build_shadow_server(payload)
    if attack.family == "mcp_rug_pull":
        return build_rugpull_server(payload)
    # Indirect injection, and jailbreak carriers delivered through a retrieval
    # surface, both plant the payload in their channel.
    if attack.family in ("indirect_prompt_injection", "jailbreak_carrier") and (
        attack.channel in CHANNELS
    ):
        return build_indirect_injection_server(payload, channel=attack.channel)
    # Excessive agency (task-only, no injection) and sensitive-info disclosure
    # (payload rides the user task) run against the plain benign toolset.
    return build_benign_server()


async def run_suite(
    suite_path: str | Path,
    make_provider: Callable[[str], Provider],
    run_id: str,
    guarded: bool = False,
) -> list[ProbeResult]:
    suite = yaml.safe_load(Path(suite_path).read_text(encoding="utf-8"))
    suite_dir = Path(suite_path).parent
    attack_paths = [_resolve(suite_dir, p) for p in suite["attacks"]]

    judge = RuleJudge()
    results: list[ProbeResult] = []

    for attack_path in attack_paths:
        attack = load_attack(attack_path)
        provider = make_provider(attack.system or DEFAULT_SYSTEM)
        server = _build_server(attack)
        guard = IOFilter() if guarded else None  # fresh per probe (counts interventions)

        start = time.perf_counter()
        async with MCPHarness(server) as harness:
            trace = await Agent(provider, harness, guard=guard).run(attack.task)
        latency_ms = int((time.perf_counter() - start) * 1000)

        outcome, hijack, detail = judge.judge(trace, attack)
        results.append(
            ProbeResult(
                run_id=run_id,
                attack_id=attack.id,
                family=attack.family,
                owasp=attack.owasp,
                atlas=attack.atlas,
                severity=attack.severity,
                provider=provider.name,
                model=provider.model,
                config="guarded" if guarded else "baseline",
                outcome=outcome,
                tool_hijack=hijack,
                guard_blocked=bool(guard and guard.interventions),
                latency_ms=latency_ms,
                judge_detail=detail,
                trace={
                    "task": trace.task,
                    "final_text": trace.final_text,
                    "stop_reason": trace.stop_reason,
                    "error": trace.error,
                    "tool_calls": [
                        {
                            "name": c.name,
                            "arguments": c.arguments,
                            "output": c.output[:MAX_OUTPUT_CHARS],
                            "blocked": c.blocked,
                        }
                        for c in trace.executed_calls
                    ],
                },
            )
        )
    return results


def _resolve(suite_dir: Path, attack_ref: str) -> Path:
    """Attack paths are given relative to the repo root; fall back to the suite dir."""
    p = Path(attack_ref)
    if p.exists():
        return p
    alt = suite_dir / attack_ref
    return alt if alt.exists() else p
