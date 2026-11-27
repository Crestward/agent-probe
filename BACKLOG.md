# agent-probe — Backlog (NOT v1.0)

Park ideas here instead of expanding v1.0. See the **Scope Freeze** in `SPEC.md`. Promote an item only when v1.0 has shipped and the item moves the headline number or the 20-second demo.

## Attack classes (v2+)
- **Reasoning-prefix / CoT injection** (BrainwashedLLM, 2611.04717). Prepend an adversarial reasoning trace so an LRM "continues" it into a harmful tool call. New capability-gating needed (only applies to models with a user-prefillable reasoning buffer; hidden-CoT o-series immune). Strong v2 attack family, but a different threat model than v1.0's MCP focus.
- **Full 20-style linguistic mutation** (2611.18601). A style-conditioned generator that rewrites each payload across 20 styles (Technical/Formal/Confident/Urgent rank highest). v1.0 keeps the generator small; the full taxonomy + BERT style-selector is v2 breadth.
- **DGA detail-elaboration generator** (2611.17818). Auxiliary LLM expands a short malicious intent into a legitimate-looking detailed request (ASR >95%). Portable to auto-generating tool-injection payloads — but it's a whole generation subsystem. v2.
- **Persona / coercive-control social-engineering class** (2611.08226). Multi-turn persona jailbreaks (role-play, authority, incremental compliance). v1.0 is single-turn-ish; multi-turn conversation-state attacks are v2.
- **Bulk external-corpus import** (AdvBench / JailbreakBench / MaliciousInstruct / HarmBench). Phase 2 represents seed→carrier *structurally* via the mutator pipeline (`attacks/generator.py`) but keeps the gold run hand-authored. Wiring the full corpora as intent sources — thousands of rows wrapped into channel payloads — would balloon the published run and dilute the curated signal; promote only after the Defence Delta (Phase 3) exists to make bulk ASR meaningful.

## Cross-model comparison (mostly done)
- **Done:** qwen2.5:7b vs **Claude Haiku 4.5** (2026-11-27) in the README/dashboard. **All target providers are now wired** — anthropic, openai, deepseek, local, and a generic **openai-compatible** (`--base-url`) for any endpoint. Users can red-team their own model.
- **Still parked:** a generic one-command **`--compare` flag** that runs several providers in one invocation (today you run each separately and diff). Small convenience; add when the cross-model story needs a one-liner. Actually *running* OpenAI/DeepSeek is only gated by the user's own keys + spend now, not by code.

## Scope-adherence guardrail (new, from the Haiku finding)
- The v1.0 I/O guardrail defends **exfiltration**, so `scope_violation` (a support bot coerced to write code / answer off-topic / swap persona) survives it on *both* models — the dashboard's visible blind spot. A second, orthogonal guardrail — a **role/scope classifier** that checks each response against the agent's declared purview before it returns — would close it. Natural "guardrail #2" once v1.0 ships; pairs with the guardrail-shootout item below.

## Defence / guardrail (v2+)
- **Adaptive / self-evolving guardrail** (GuardrailAgent, 2611.09734). Multi-agent input+output detector that crawls new jailbreaks and promotes missed attacks via a feedback loop (~90 examples → 0.80 detection). Reverse it as a red-team target: test whether agent-probe's attacks survive an *adapting* defender. Great story, big build. v2.
- **Guardrail shootout.** v1.0 benchmarks ONE guardrail for the Defence Delta. Comparing Llama-Guard / Qwen-Guard / MLS-filter / style-aware-DPO is v2.
- **Style-aware DPO defence** (2611.18601): fine-tune a defence that's robust to style attacks (ASR 86%→19.5%). Requires training — out of v1.0 scope.

## Methodology / positioning (nice-to-have)
- **8-feature standards-alignment scorecard** (2611.04271): Accessibility/Transparency, Standardization, Evidence/Documentation, Automation/Integration, Coverage, Assessment Environments, Activity/Updates, Effectiveness. Could become a README comparison table vs Garak/PyRIT/Promptfoo/Giskard. Low cost — consider for Week 5 polish, not core.
- **NIST AI 100-2 E2025** taxonomy as a third mapping axis alongside OWASP + ATLAS. Adds credibility; adds mapping work. Week 5 if time.
- **Multi-turn / trajectory-aware evaluation** (2611.08226 critique): log the full interaction trajectory, not just the final verdict. v1.0 already captures traces; full multi-turn scoring is v2.
