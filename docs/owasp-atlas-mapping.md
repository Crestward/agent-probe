# OWASP LLM Top-10 ↔ MITRE ATLAS mapping

Every attack in `attacks/gold/` carries an `owasp:` id and an `atlas:` technique id.
This table is the authority for those ids. The ATLAS ids were verified against the
live MITRE ATLAS matrix (atlas.mitre.org / d3fend.mitre.org) on **2026-11-26**.

## Technique ids used

| ATLAS id | Technique | ATLAS tactic | Verified |
|---|---|---|---|
| `AML.T0051` | LLM Prompt Injection | Initial Access / Execution | ✅ |
| `AML.T0051.000` | — Direct Prompt Injection (payload in the user turn) | — | ✅ |
| `AML.T0051.001` | — Indirect Prompt Injection (payload in retrieved data / tool metadata) | — | ✅ |
| `AML.T0051.002` | — Meta-prompt Extraction | — | ✅ |
| `AML.T0054` | LLM Jailbreak (override safety/alignment) | Defense Evasion | ✅ |
| `AML.T0056` | Extract LLM System Prompt | Exfiltration / Collection | ✅ |
| `AML.T0057` | LLM Data Leakage (sensitive data in model output) | Exfiltration | ✅ |
| `AML.T0086` | Exfiltration via AI Agent Tool Invocation | Exfiltration | ✅ |

## Family → OWASP → ATLAS

| agent-probe family | OWASP LLM Top-10 (2026) | ATLAS technique | Rationale |
|---|---|---|---|
| `indirect_prompt_injection` | LLM01 Prompt Injection | `AML.T0051.001` | Payload planted in retrieved data (email, document, CRM field, ticket, web page). |
| `mcp_tool_poisoning` | LLM01 / LLM03 | `AML.T0051.001` | Instruction hidden in a tool's `description`, ingested like any other indirect source. |
| `mcp_tool_shadowing` | LLM03 Excessive Agency | `AML.T0051.001` | A malicious tool's metadata rewrites how a *trusted* tool is used. |
| `mcp_rug_pull` | LLM03 Excessive Agency | `AML.T0051.001` | Tool clean at approval, mutates to inject on a later call. |
| `excessive_agency` | LLM03 Excessive Agency | `AML.T0086` | The agent takes a consequential tool action beyond the user's intent — no injection. |
| `sensitive_info_disclosure` (data) | LLM02 Sensitive Info Disclosure | `AML.T0057` | A stored secret / other-party data leaks into the agent's answer. |
| `sensitive_info_disclosure` (system prompt) | LLM02 Sensitive Info Disclosure | `AML.T0056` | The agent reveals its own system prompt / configuration canary. |
| `jailbreak_carrier` | LLM01 Prompt Injection | `AML.T0054` | A delivery wrapper (roleplay, base64, many-shot, refusal-suppression) layered on an exfil payload. |
| `scope_violation` | LLM03 Excessive Agency | `AML.T0054` | A role-scoped agent (support bot, HR helpdesk) coerced to act outside its purview — write code, answer off-topic, swap persona. |

> **Notes on mapping judgement.** MCP tool-poisoning/shadowing/rug-pull are *agentic*
> delivery surfaces for prompt injection; ATLAS does not (as of this date) have a
> dedicated MCP sub-technique, so they map to Indirect Prompt Injection
> (`AML.T0051.001`) with the excessive-agency *impact* captured by OWASP LLM03. Where
> an injection *results in* an exfiltrating tool call, `AML.T0086` is the more specific
> exfiltration technique; we tag the injection vector on the injection families and
> reserve `AML.T0086` for the no-injection `excessive_agency` family to keep the
> mapping one-to-one and legible.
>
> **`scope_violation` is a weak ATLAS fit on purpose.** A role-scoped agent doing
> off-purview work (a support bot writing code) is primarily a *governance / misuse*
> failure, not a catalogued adversarial technique. When the request overrides the
> role ("ignore your support role", "you are now DevBot") it is jailbreak-shaped, so
> we map it to `AML.T0054`; OWASP LLM03 (excessive *functionality* — capability
> beyond the agent's purpose) is the more natural home. This is flagged rather than
> forced.

## Sources

- MITRE ATLAS matrix — <https://atlas.mitre.org/>
- `AML.T0051` LLM Prompt Injection (and sub-techniques) — MITRE ATLAS
- `AML.T0054` LLM Jailbreak — <https://d3fend.mitre.org/offensive-technique/attack/AML.T0054/>
- `AML.T0056` Extract LLM System Prompt — <https://d3fend.mitre.org/offensive-technique/attack/AML.T0056/>
- `AML.T0057` LLM Data Leakage — MITRE ATLAS (Exfiltration)
- `AML.T0086` Exfiltration via AI Agent Tool Invocation — MITRE ATLAS (2026 agent techniques)
