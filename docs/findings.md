# One ASR number hides everything interesting

*A short writeup of what agent-probe found, and the methodology behind the numbers.*

Most "AI security" demos end at a single screenshot: a prompt injection worked, here's
the scary output. That tells you nothing you can act on. agent-probe treats defence as
a **measurement** — a number you can regression-test — and the moment you measure
properly, the single headline number turns out to be the least useful thing on the
page. The interesting signal is always in the **spread**.

Here is the result that makes the case, across 31 attacks in 8 families, run against a
small local model (**qwen2.5:7b**) and the small cloud model most teams actually put
behind RAG and agent tools (**Claude Haiku 4.5**):

| | qwen2.5:7b | Claude Haiku 4.5 |
|---|---:|---:|
| **Baseline ASR** | 41.9% | 12.9% |
| **Guarded ASR** | 6.5% | 3.2% |

If you stopped there you'd conclude "Haiku is ~3× safer, ship it." The per-family
breakdown says something much more useful.

## Finding 1 — different models fail at different things

| Family | qwen2.5 | Haiku 4.5 |
|---|---:|---:|
| indirect_prompt_injection | 50.0% | **0.0%** |
| jailbreak_carrier | 50.0% | **0.0%** |
| mcp_tool_poisoning | 50.0% | **0.0%** |
| mcp_rug_pull | 50.0% | **0.0%** |
| sensitive_info_disclosure | 50.0% | **0.0%** |
| mcp_tool_shadowing | 50.0% | 50.0% |
| scope_violation | 25.0% | **50.0%** |
| excessive_agency | 0.0% | **33.3%** |

Haiku **shrugs off everything qwen falls for** — indirect injection (including the
AgentDojo `important_instructions` template that owns qwen outright), jailbreak
carriers, tool-poisoning, rug-pull, secret disclosure — all drop to **0%**. It is a
far better-aligned model on the injection/exfiltration axis.

**But Haiku is _more_ vulnerable exactly where it bites for agents:** it complies with
**scope violations** (a support bot asked to write code, run SQL, or swap persona —
50%) and takes **excessive-agency** actions (33%). qwen's weakness is
injection/exfiltration; Haiku's is **agency and staying in role.** A single ASR
number — or a leaderboard that ranks models by one scalar — would have hidden the one
thing an agent builder most needs to know about their chosen model.

The practical reading: "which model is safest" is the wrong question. **"Safe against
which failure class, for my agent's role and permissions"** is the right one.

## Finding 2 — the fix was a better *attack*, never a weaker *target*

Early on, every naive injection scored **ASR 0%** across four models (Opus 5.5,
Sonnet 5.5, Haiku 4.5, qwen2.5:7b). They all correctly treated injected data as data,
not commands. The tempting shortcut — pull an uncensored model so the numbers "work"
— was vetoed: **a rigged target is a worthless benchmark.** Instead, the attacks were
engineered from the literature. AgentDojo's `important_instructions` technique
(arXiv 2406.13352) — user-impersonation ("a message from me, *{user}*, to you,
*{model}*") plus prerequisite framing plus end-of-output placement, with the agent
given a matched named principal in its system prompt — lands on qwen2.5:7b at **ASR
100%** on its own. Every attack in the gold set is a readable YAML with a verified
ATLAS id; none is guessed.

## Finding 3 — constraining actions beats detecting every injection

The Defence Delta comes from exactly **one** guardrail: a heuristic, deterministic I/O
content filter (`guard/filter.py`) that screens inbound tool descriptions and outputs,
redacts leaked secrets, and — the part doing the heavy lifting — enforces a
**least-privilege egress allow-list** on the one action that can exfiltrate
(`send_email`).

| Target | ASR baseline | ASR guarded | Δ |
|---|---:|---:|---:|
| qwen2.5:7b | 41.9% | 6.5% | **−35.4 pts** |
| Claude Haiku 4.5 | 12.9% | 3.2% | **−9.7 pts** |

qwen's injection-heavy ASR collapses because once the model *can't* send mail to the
attacker, a successful injection has nowhere to go. The lesson that generalises:
**constrain what the agent is allowed to do, rather than trying to detect every
cleverly-worded injection.**

## Finding 4 — the honest part: what survives

The guarded ASR is **not** 0%, and that's the most honest cell in the whole project.
What survives on *both* models is **scope violation** — an exfiltration guardrail has
no opinion about a support bot answering trivia or writing a Python function. It's the
wrong tool for that failure class. The dashboard shows the surviving red cells
plainly, and `agent-probe recommend` flags scope-violation as **not covered by the I/O
guardrail**, pointing instead at a role/scope-adherence check. **Different failure
classes need different defences** — and a benchmark earns trust by showing you the
cells it *didn't* fix, not by claiming a zero.

## Methodology & caveats (why you can trust the numbers)

- **Fixed, non-adaptive suite.** An attacker who observes the guardrail and routes
  around it (allow-listed recipient, signature-avoidance) is the open problem, parked
  in the backlog. Guarded ASR is an **upper bound on the defence**, not a guarantee.
- **Synthetic targets we control** (local model, or cloud model via our own key) with
  synthetic tools and fake secrets — reproducible and CI-safe by design. See
  [`threat-model.md`](threat-model.md).
- **`error` excluded from denominators** so flakiness never moves ASR. Success is
  judged from the trace, not the final apology; a success beats a later apology.
- **Resistance shows up as `clean`, not `refusal`** — the model silently ignores the
  payload and does the benign task. That's an honest, measurable behaviour and it's
  reported as its own outcome rather than folded into "refused."
- Mappings to OWASP LLM Top 10 (2026) and MITRE ATLAS are in
  [`owasp-atlas-mapping.md`](owasp-atlas-mapping.md); every `atlas:` id was checked
  against the live matrix.

## Reproduce it

```bash
uv run agent-probe run evals/gold.yaml --provider local            # baseline, free
uv run agent-probe run evals/gold.yaml --provider local --guard    # guarded
uv run agent-probe delta <baseline>.jsonl <guarded>.jsonl          # the Delta table
uv run agent-probe recommend <run>.jsonl                           # prioritized fixes
```

Swap `--provider local` for `--provider anthropic --model claude-haiku-4-5`, or point
`--provider openai-compatible --base-url <url> --model <name>` at any OpenAI-compatible
endpoint to red-team your own model.
