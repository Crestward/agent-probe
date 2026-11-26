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


# --------------------------------------------------------------------------- #
# Attacks
# --------------------------------------------------------------------------- #


class SuccessCondition(BaseModel):
    """How the rule-based judge decides a probe succeeded."""

    tool_called: str | None = None
    arg_contains: dict[str, str] = Field(default_factory=dict)


class AttackSpec(BaseModel):
    """A declarative attack (SPEC §4). Loaded from YAML in attacks/."""

    id: str
    family: str
    owasp: str
    atlas: str | None = None
    channel: str
    severity: str = "medium"
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
    outcome: Outcome
    tool_hijack: bool
    latency_ms: int
    judge_detail: str
    trace: dict[str, Any]
