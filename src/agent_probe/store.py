"""Persist probe results as JSONL, with a queryable SQLite mirror (SPEC §6).

JSONL is the source of truth (append-friendly, feeds the dashboard). The SQLite
mirror exists for ad-hoc querying and is indexed by owasp / atlas / family so
"show me every LLM03 success" is a one-liner.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from pathlib import Path

from agent_probe.models import ProbeResult


def write_results(path: str | Path, results: Sequence[ProbeResult]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        for r in results:
            f.write(r.model_dump_json() + "\n")


_SCHEMA = """
CREATE TABLE IF NOT EXISTS probes (
    run_id      TEXT,
    attack_id   TEXT,
    family      TEXT,
    owasp       TEXT,
    atlas       TEXT,
    severity    TEXT,
    provider    TEXT,
    model       TEXT,
    outcome     TEXT,
    tool_hijack INTEGER,
    latency_ms  INTEGER,
    judge_detail TEXT,
    trace       TEXT
);
CREATE INDEX IF NOT EXISTS ix_probes_owasp  ON probes(owasp);
CREATE INDEX IF NOT EXISTS ix_probes_atlas  ON probes(atlas);
CREATE INDEX IF NOT EXISTS ix_probes_family ON probes(family);
"""


def write_sqlite(db_path: str | Path, results: Sequence[ProbeResult]) -> None:
    """Append results into a SQLite table indexed by owasp / atlas / family."""
    p = Path(db_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(p)
    try:
        conn.executescript(_SCHEMA)
        conn.executemany(
            "INSERT INTO probes VALUES "
            "(:run_id,:attack_id,:family,:owasp,:atlas,:severity,:provider,:model,"
            ":outcome,:tool_hijack,:latency_ms,:judge_detail,:trace)",
            [
                {
                    "run_id": r.run_id,
                    "attack_id": r.attack_id,
                    "family": r.family,
                    "owasp": r.owasp,
                    "atlas": r.atlas,
                    "severity": r.severity,
                    "provider": r.provider,
                    "model": r.model,
                    "outcome": r.outcome.value,
                    "tool_hijack": int(r.tool_hijack),
                    "latency_ms": r.latency_ms,
                    "judge_detail": r.judge_detail,
                    "trace": json.dumps(r.trace),
                }
                for r in results
            ],
        )
        conn.commit()
    finally:
        conn.close()


def append_result(path: str | Path, result: ProbeResult) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(result.model_dump_json() + "\n")


def read_results(path: str | Path) -> list[ProbeResult]:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [ProbeResult.model_validate_json(line) for line in lines if line.strip()]
