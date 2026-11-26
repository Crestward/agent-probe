"""Load a single attack spec from YAML. Phase 2 generalizes this into a catalog."""

from __future__ import annotations

from pathlib import Path

import yaml

from agent_probe.models import AttackSpec


def load_attack(path: str | Path) -> AttackSpec:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return AttackSpec(**data)
