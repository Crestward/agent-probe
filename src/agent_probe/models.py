"""Shared data model for agent-probe.

Runtime types (provider I/O, agent trace) are dataclasses; persisted/validated
types (attack specs, probe results, metrics) are pydantic models.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --------------------------------------------------------------------------- #
# Provider I/O (neutral across Anthropic / OpenAI / DeepSeek)
# --------------------------------------------------------------------------- #


@dataclass
class ToolSpec:
    """A tool offered to the agent, normalized from an MCP tool definition."""

    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass
class ToolCall:
    """A tool invocation the model requested."""

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class Msg:
    """A neutral conversation entry.

    `raw` holds the provider's native assistant content so it can be echoed back
    verbatim on the next turn (required by Anthropic to preserve thinking/tool
    blocks). It is only ever produced and consumed by the same provider.
    """

    role: str  # "user" | "assistant" | "tool_results"
    text: str | None = None
    raw: Any = None
    tool_results: list[tuple[str, str]] | None = None  # (tool_call_id, output)


@dataclass
class Completion:
    """One model turn."""

    text: str
    tool_calls: list[ToolCall]
    stop_reason: str
    raw: Any = None
    input_tokens: int = 0
    output_tokens: int = 0


# --------------------------------------------------------------------------- #
# Outcomes & metrics
# --------------------------------------------------------------------------- #


class Outcome(StrEnum):
    """The 4-way probe partition (SPEC §3). ERROR is excluded from rate denominators."""

    SUCCESS = "success"
    REFUSAL = "refusal"
    CLEAN_COMPLETION = "clean_completion"
    ERROR = "error"


# Harm weights by severity (SPEC §3 harm-weighted ASR). A critical data-exfil
# breach should not be diluted by many trivial attacks.
SEVERITY_WEIGHT: dict[str, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class Metrics(BaseModel):
    n_total: int
    n_scored: int
    n_error: int
    successes: int
    refusals: int
    clean_completions: int
    tool_hijacks: int
    asr: float
    rr: float
    clean_completion_rate: float
    tool_hijack_rate: float
    harm_weighted_asr: float = 0.0


class GroupMetrics(BaseModel):
    """A per-dimension (OWASP id / family) slice of the headline numbers."""

    group: str
    n_scored: int
    n_error: int
    successes: int
    asr: float
    rr: float
    tool_hijack_rate: float


# --------------------------------------------------------------------------- #
# Attacks
# --------------------------------------------------------------------------- #


class SuccessCondition(BaseModel):
    """How the rule-based judge decides a probe succeeded.

    Two independent success routes (either fires):
      - a tool-call hijack: `tool_called` with every `arg_contains` substring, or
      - a disclosure: the agent's final answer contains any `text_contains` marker
        (used for sensitive-info-disclosure / system-prompt extraction, where the
        harm is in the *answer*, not a tool call).
    """

    tool_called: str | None = None
    arg_contains: dict[str, str] = Field(default_factory=dict)
    text_contains: list[str] = Field(default_factory=list)


# The attack families (SPEC §4). The MCP triad counts as one family but has three
# distinct target servers, so it is three values here.
KNOWN_FAMILIES: frozenset[str] = frozenset(
    {
        "indirect_prompt_injection",
        "mcp_tool_poisoning",
        "mcp_tool_shadowing",
        "mcp_rug_pull",
        "excessive_agency",
        "sensitive_info_disclosure",
        "jailbreak_carrier",
    }
)


class AttackSpec(BaseModel):
    """A declarative attack (SPEC §4). Loaded from YAML in attacks/."""

    id: str
    family: str
    owasp: str
    atlas: str | None = None
    channel: str
    severity: str = "medium"
    technique: str | None = None  # e.g. "important_instructions", "naive" — for reporting
    task: str
    payload: str | None = None
    success_when: SuccessCondition = Field(default_factory=SuccessCondition)


# --------------------------------------------------------------------------- #
# Trace & result
# --------------------------------------------------------------------------- #


@dataclass
class ExecutedCall:
    name: str
    arguments: dict[str, Any]
    output: str
    blocked: bool = False  # the guardrail intercepted this call before it took effect


@dataclass
class Trace:
    """Everything that happened during one agent run."""

    task: str
    executed_calls: list[ExecutedCall] = field(default_factory=list)
    final_text: str = ""
    error: str | None = None
    halted: bool = False  # hit max_steps without a natural end_turn
    stop_reason: str = ""  # stop_reason of the final model turn


class ProbeResult(BaseModel):
    """One scored probe, persisted to JSONL."""

    run_id: str
    attack_id: str
    family: str
    owasp: str
    atlas: str | None = None
    severity: str
    provider: str
    model: str
    config: str = "baseline"  # "baseline" | "guarded" (SPEC §3 Defence Delta)
    outcome: Outcome
    tool_hijack: bool
    guard_blocked: bool = False  # the guardrail intervened on this probe
    latency_ms: int
    judge_detail: str
    trace: dict[str, Any]


class DefenceDelta(BaseModel):
    """ASR before vs after the guardrail on the same suite (SPEC §3, the money metric)."""

    group: str  # "overall" or a family / owasp id
    n: int
    asr_baseline: float
    asr_guarded: float
    delta: float  # baseline - guarded (positive = guardrail helped)
    guard_pass_rate: float = 0.0  # fraction the guardrail let through unblocked
    asr_behind_filter: float = 0.0  # ASR among probes the guardrail did NOT block
