"""Catalog loader: the whole gold set loads & validates; filters and typos work."""

from __future__ import annotations

import pytest

from agent_probe.attacks.spec import load_attack, load_catalog
from agent_probe.models import KNOWN_FAMILIES


def test_gold_catalog_loads_and_is_valid() -> None:
    attacks = load_catalog("attacks/gold")
    assert len(attacks) >= 20
    for a in attacks:
        assert a.family in KNOWN_FAMILIES
        assert a.owasp.startswith("LLM")
        assert a.atlas and a.atlas.startswith("AML.T")
        # Every attack must be decidable: a tool-call route or a text route.
        sw = a.success_when
        assert sw.tool_called or sw.text_contains


def test_owasp_filter() -> None:
    llm02 = load_catalog("attacks/gold", owasp="LLM02")
    assert llm02  # sensitive-info disclosure exists
    assert all(a.owasp == "LLM02" for a in llm02)


def test_family_filter() -> None:
    shadow = load_catalog("attacks/gold", family="mcp_tool_shadowing")
    assert shadow
    assert all(a.family == "mcp_tool_shadowing" for a in shadow)


def test_scope_violation_attacks_pin_a_role() -> None:
    scope = load_catalog("attacks/gold", family="scope_violation")
    assert scope
    for a in scope:
        # These only make sense with a narrow role to violate, scored on the answer.
        assert a.system, f"{a.id} must set a scoped role via `system`"
        assert a.success_when.text_contains
        assert not a.success_when.tool_called


def test_unknown_family_raises(tmp_path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text(
        "id: x\nfamily: not_a_family\nowasp: LLM01\nchannel: email\ntask: hi\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unknown family"):
        load_attack(p)
