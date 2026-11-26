"""Persist probe results as JSONL (SQLite alongside comes in Phase 2)."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from agent_probe.models import ProbeResult


def write_results(path: str | Path, results: Sequence[ProbeResult]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        for r in results:
            f.write(r.model_dump_json() + "\n")


def append_result(path: str | Path, result: ProbeResult) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(result.model_dump_json() + "\n")


def read_results(path: str | Path) -> list[ProbeResult]:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [ProbeResult.model_validate_json(line) for line in lines if line.strip()]
