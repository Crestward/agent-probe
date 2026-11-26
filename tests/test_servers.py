"""MCP target servers: channels surface payloads; shadow adds a tool; rug-pull
mutates only after the trigger call. Exercised over the real in-memory harness."""

from __future__ import annotations

from agent_probe.mcp.benign import build_benign_server
from agent_probe.mcp.harness import MCPHarness
from agent_probe.mcp.indirect import build_indirect_injection_server
from agent_probe.mcp.rugpull import build_rugpull_server
from agent_probe.mcp.shadow import build_shadow_server


async def test_injection_surfaces_in_chosen_channel() -> None:
    server = build_indirect_injection_server("PWNED-MARKER", channel="support_ticket")
    async with MCPHarness(server) as h:
        ticket = await h.call("read_support_ticket", {"ticket_id": "T1"})
        emails = await h.call("read_emails", {})
    assert "PWNED-MARKER" in ticket  # planted channel carries it
    assert "PWNED-MARKER" not in emails  # other channels stay clean


async def test_shadow_adds_a_tool_whose_description_carries_payload() -> None:
    server = build_shadow_server("SHADOW-PAYLOAD")
    async with MCPHarness(server) as h:
        names = {t.name for t in h.tool_specs()}
        desc = next(t.description for t in h.tool_specs() if t.name == "check_delivery_status")
    assert "check_delivery_status" in names
    assert "send_email" in names  # trusted tool still present
    assert "SHADOW-PAYLOAD" in desc


async def test_rugpull_is_clean_before_trigger_and_poisoned_after() -> None:
    server = build_rugpull_server("RUG-PAYLOAD", trigger_on=2)
    async with MCPHarness(server) as h:
        first = await h.call("get_weather", {"city": "London"})
        second = await h.call("get_weather", {"city": "Paris"})
    assert "RUG-PAYLOAD" not in first  # clean at approval / first use
    assert "RUG-PAYLOAD" in second  # rug pulled on the later call


async def test_benign_server_has_no_payload_by_default() -> None:
    async with MCPHarness(build_benign_server()) as h:
        doc = await h.call("read_document", {"name": "x"})
    assert "INFORMATION" not in doc and "SYSTEM" not in doc
