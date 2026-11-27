"""Remediation engine: turn findings into the *measures the operator should take*.

The rest of the tool measures the defence. This module prescribes it: for each
attack family that still lands, it emits prioritized, concrete mitigations mapped
to the public taxonomies (OWASP LLM Top-10 / MITRE ATLAS). The knowledge base is
hand-curated from the families' real-world countermeasures — not model-generated —
so the advice is specific and auditable.

`covered_by_guardrail` flags whether agent-probe's own v1.0 I/O guardrail already
addresses a family, so the report can separate "turn on the guardrail" from "this
needs a defence the guardrail does not provide" (e.g. scope violation).
"""

from __future__ import annotations

from collections.abc import Sequence

from agent_probe.models import SEVERITY_WEIGHT, Outcome, ProbeResult, Recommendation

# family -> (summary, ordered concrete actions, references, covered_by_v1_guardrail)
_KB: dict[str, dict] = {
    "indirect_prompt_injection": {
        "summary": "Untrusted retrieved data (emails, docs, tickets, pages) is being "
        "obeyed as instructions.",
        "actions": [
            "Spotlight/delimit tool output: wrap retrieved content in explicit "
            "boundaries and instruct the model to treat it as data, never commands.",
            "Screen inbound tool output for injection signatures before it re-enters "
            "the context (agent-probe's guardrail does this).",
            "Keep a hard instruction hierarchy: tool/retrieved content must never "
            "override the system prompt or the user's original task.",
            "Require explicit human confirmation for state-changing actions that are "
            "triggered while processing retrieved data.",
        ],
        "refs": ["OWASP LLM01", "ATLAS AML.T0051.001"],
        "covered": True,
    },
    "mcp_tool_poisoning": {
        "summary": "Hidden instructions in a tool's description are being executed.",
        "actions": [
            "Treat tool descriptions as untrusted input: sanitize/screen them before "
            "they reach the model (agent-probe's guardrail does this).",
            "Pin and hash tool definitions at approval time; alert on any change.",
            "Allow-list MCP servers and verify their provenance before connecting.",
        ],
        "refs": ["OWASP LLM01 / LLM03", "ATLAS AML.T0051.001"],
        "covered": True,
    },
    "mcp_tool_shadowing": {
        "summary": "One tool's metadata is rewriting how a trusted tool behaves.",
        "actions": [
            "Isolate tool definitions: never let one tool's description set rules for "
            "another tool (cross-tool instructions are a red flag to strip).",
            "Sanitize all tool descriptions; pin definitions at approval.",
            "Scope each MCP server's influence to its own tools only.",
        ],
        "refs": ["OWASP LLM03", "ATLAS AML.T0051.001"],
        "covered": True,
    },
    "mcp_rug_pull": {
        "summary": "A tool approved as benign is mutating to malicious on later calls.",
        "actions": [
            "Hash tool definitions at approval and re-verify on every invocation; "
            "refuse a tool whose definition changed.",
            "Re-screen tool OUTPUT on every call, not just at connect time "
            "(agent-probe's guardrail does this).",
            "Prefer immutable, versioned tool registries over live-mutable servers.",
        ],
        "refs": ["OWASP LLM03", "ATLAS AML.T0051.001"],
        "covered": True,
    },
    "excessive_agency": {
        "summary": "The agent takes consequential actions beyond the user's intent.",
        "actions": [
            "Apply least privilege: remove high-impact tools the agent does not need.",
            "Gate irreversible/high-impact actions (send, pay, delete) behind explicit "
            "human-in-the-loop confirmation.",
            "Constrain permissions per task/session rather than granting blanket access.",
        ],
        "refs": ["OWASP LLM03", "ATLAS AML.T0086"],
        "covered": False,  # the egress allow-list helps only when the recipient is off-list
    },
    "sensitive_info_disclosure": {
        "summary": "Secrets, credentials, or the system prompt are leaking into answers.",
        "actions": [
            "Filter outputs for secrets/PII (DLP) before returning them "
            "(agent-probe's guardrail redacts known markers).",
            "Keep secrets out of the model's context: fetch them tool-side behind an "
            "authz check; use a vault, not the system prompt.",
            "Treat the system prompt as public; add canary tokens to detect extraction.",
        ],
        "refs": ["OWASP LLM02", "ATLAS AML.T0057 / AML.T0056"],
        "covered": True,
    },
    "jailbreak_carrier": {
        "summary": "Encoded / roleplay / many-shot wrappers are smuggling payloads past "
        "the model's guard.",
        "actions": [
            "Add an input guard / jailbreak classifier (prompt-guard class) ahead of "
            "the agent.",
            "Decode and re-scan encoded content (base64/rot13); never execute decoded "
            "instructions automatically.",
            "Combine with egress controls so a successful jailbreak still cannot exfil.",
        ],
        "refs": ["OWASP LLM01", "ATLAS AML.T0054"],
        "covered": False,  # screening catches some carriers; egress controls catch the rest
    },
    "scope_violation": {
        "summary": "The agent is being coerced out of its defined role (off-task, "
        "persona swap, unrelated work).",
        "actions": [
            "Add a role/scope-adherence check: validate each response against the "
            "agent's declared purview and refuse off-scope output.",
            "Separate capabilities at the routing layer: do not give a narrow agent "
            "general-purpose tools (e.g. code execution for a support bot).",
            "Reinforce scope in the system prompt and gate outputs to the domain.",
        ],
        "refs": ["OWASP LLM03", "ATLAS AML.T0054"],
        "covered": False,  # the exfiltration guardrail does NOT address scope abuse
    },
}

_PRIORITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def recommend(
    results: Sequence[ProbeResult], min_asr: float = 0.0
) -> list[Recommendation]:
    """Prioritized mitigations for every family whose ASR exceeds `min_asr`.

    Sorted most-urgent first (priority band, then ASR). Families with no successes
    are omitted — you only get told to fix what actually broke.
    """
    by_family: dict[str, list[ProbeResult]] = {}
    for r in results:
        by_family.setdefault(r.family, []).append(r)

    recs: list[Recommendation] = []
    for family, rows in by_family.items():
        scored = [r for r in rows if r.outcome != Outcome.ERROR]
        if not scored:
            continue
        successes = [r for r in scored if r.outcome == Outcome.SUCCESS]
        asr = len(successes) / len(scored)
        if asr <= min_asr:
            continue
        kb = _KB.get(family)
        if kb is None:
            continue
        recs.append(
            Recommendation(
                family=family,
                owasp=scored[0].owasp,
                atlas=scored[0].atlas,
                priority=_priority(asr, successes),
                asr=asr,
                n_success=len(successes),
                n=len(scored),
                finding=kb["summary"],
                actions=kb["actions"],
                refs=kb["refs"],
                covered_by_guardrail=kb["covered"],
            )
        )

    recs.sort(key=lambda r: (_PRIORITY_ORDER[r.priority], -r.asr))
    return recs


def _priority(asr: float, successes: Sequence[ProbeResult]) -> str:
    """High if it lands often or the successes are severe or exfiltrating."""
    severe = any(
        r.tool_hijack or SEVERITY_WEIGHT.get(r.severity, 2) >= SEVERITY_WEIGHT["high"]
        for r in successes
    )
    if asr >= 0.5 or (asr > 0 and severe):
        return "high"
    if asr >= 0.2:
        return "medium"
    return "low"
