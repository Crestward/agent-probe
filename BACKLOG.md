# agent-probe — Backlog (NOT v1.0)

Park ideas here instead of expanding v1.0. See the **Scope Freeze** in `SPEC.md`. Promote an item only when v1.0 has shipped and the item moves the headline number or the 20-second demo.

## Attack classes (v2+)
- **Reasoning-prefix / CoT injection** (BrainwashedLLM, 2611.04717). Prepend an adversarial reasoning trace so an LRM "continues" it into a harmful tool call. New capability-gating needed (only applies to models with a user-prefillable reasoning buffer; hidden-CoT o-series immune). Strong v2 attack family, but a different threat model than v1.0's MCP focus.
- **Full 20-style linguistic mutation** (2611.18601). A style-conditioned generator that rewrites each payload across 20 styles (Technical/Formal/Confident/Urgent rank highest). v1.0 keeps the generator small; the full taxonomy + BERT style-selector is v2 breadth.
- **DGA detail-elaboration generator** (2611.17818). Auxiliary LLM expands a short malicious intent into a legitimate-looking detailed request (ASR >95%). Portable to auto-generating tool-injection payloads — but it's a whole generation subsystem. v2.
- **Persona / coercive-control social-engineering class** (2611.08226). Multi-turn persona jailbreaks (role-play, authority, incremental compliance). v1.0 is single-turn-ish; multi-turn conversation-state attacks are v2.

## Defence / guardrail (v2+)
- **Adaptive / self-evolving guardrail** (GuardrailAgent, 2611.09734). Multi-agent input+output detector that crawls new jailbreaks and promotes missed attacks via a feedback loop (~90 examples → 0.80 detection). Reverse it as a red-team target: test whether agent-probe's attacks survive an *adapting* defender. Great story, big build. v2.
- **Guardrail shootout.** v1.0 benchmarks ONE guardrail for the Defence Delta. Comparing Llama-Guard / Qwen-Guard / MLS-filter / style-aware-DPO is v2.
- **Style-aware DPO defence** (2611.18601): fine-tune a defence that's robust to style attacks (ASR 86%→19.5%). Requires training — out of v1.0 scope.

## Methodology / positioning (nice-to-have)
- **8-feature standards-alignment scorecard** (2611.04271): Accessibility/Transparency, Standardization, Evidence/Documentation, Automation/Integration, Coverage, Assessment Environments, Activity/Updates, Effectiveness. Could become a README comparison table vs Garak/PyRIT/Promptfoo/Giskard. Low cost — consider for Week 5 polish, not core.
- **NIST AI 100-2 E2025** taxonomy as a third mapping axis alongside OWASP + ATLAS. Adds credibility; adds mapping work. Week 5 if time.
- **Multi-turn / trajectory-aware evaluation** (2611.08226 critique): log the full interaction trajectory, not just the final verdict. v1.0 already captures traces; full multi-turn scoring is v2.
