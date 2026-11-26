"""Load attack specs from YAML — a single file or a whole catalog directory.

The catalog is declarative data (SPEC §4): adding attacks never touches code.
Loading validates every spec (pydantic) and checks the `family` is one we know
how to stand a target up for, so a typo fails loudly instead of silently running
against the wrong server.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import yaml

from agent_probe.models import KNOWN_FAMILIES, AttackSpec


def load_attack(path: str | Path) -> AttackSpec:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    attack = AttackSpec(**data)
    if attack.family not in KNOWN_FAMILIES:
        raise ValueError(
            f"{path}: unknown family {attack.family!r}; expected one of {sorted(KNOWN_FAMILIES)}"
        )
    return attack


def load_catalog(
    directory: str | Path = "attacks/gold",
    owasp: str | None = None,
    family: str | None = None,
) -> list[AttackSpec]:
    """Load and validate every `*.yaml` under `directory`, sorted by id.

    Optional `owasp` / `family` filters narrow the set (for `agent-probe list`).
    """
    paths = sorted(Path(directory).glob("*.yaml"))
    attacks = [load_attack(p) for p in paths]
    return _filter(attacks, owasp=owasp, family=family)


def _filter(
    attacks: Iterable[AttackSpec], owasp: str | None = None, family: str | None = None
) -> list[AttackSpec]:
    out = list(attacks)
    if owasp:
        out = [a for a in out if a.owasp.lower() == owasp.lower()]
    if family:
        out = [a for a in out if a.family == family]
    return out
