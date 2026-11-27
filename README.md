# agent-probe

> **Attack LLM agents and their MCP tool servers — then _measure the defence_.**
> agent-probe reports Attack Success Rate, Refusal Rate and tool-hijack rate,
> mapped to the **OWASP LLM Top 10 (2026)** and **MITRE ATLAS**, with CI gating
> and a live results dashboard.

🚧 **Under construction** — building in public. See [`SPEC.md`](SPEC.md) for the
design, [`tasks.md`](tasks.md) for the phased build plan, and [`BACKLOG.md`](BACKLOG.md)
for what's deliberately out of v1.0 scope.

Most "AI security" projects are a prompt-injection demo in a notebook. This one is a
**measurement instrument**: it treats defence as a number you can regression-test.

**▶ Live dashboard:** <https://claude.ai/artifact/32w8WqpHb8XJL51jWBG4wC> — interactive
**cross-model** scoreboard (qwen2.5 vs Claude Haiku 4.5), Defence Delta, outcome
heatmap, and a **trace explorer** (click any probe to see the exact tool calls that
led to the breach, with a baseline↔guarded toggle). _(Private preview; built by
`dashboard/build.py` from the committed snapshots. A public GitHub Pages deploy
follows once the repo is pushed.)_

## Status

| Phase | What | State |
|---|---|---|
| 0 | Foundation & scaffolding | ✅ done |
| 1 | Vertical slice (one real attack → one real number) | ✅ done |
| 2 | Breadth: 5 attack families, published results table | ✅ done |
| 3 | Defence Delta + cross-model (qwen vs Haiku 4.5) | ✅ done |
| 4 | Dashboard ✅ · CI gate + hardened judge | 🚧 |
| 5 | Polish, writeup & OSS contribution | ⬜ |

<!-- HERO-RESULTS:START -->
## Results — 31 attacks, two targets

Every attack is run against a local **qwen2.5:7b** and **Claude Haiku 4.5** (the
small, fast model most teams actually put behind RAG and agent tools), baseline and
with one guardrail. The headline is the **spread** — a single ASR number hides
everything interesting; the per-family breakdown shows that *different models fail
at different things.*

| | qwen2.5:7b (local) | Claude Haiku 4.5 |
|---|---:|---:|
| **Baseline ASR** | **41.9%** | **12.9%** |
| **Guarded ASR** | 6.5% | 3.2% |
| Refusal rate (baseline) | 9.7% | 19.4% |

### Baseline ASR by attack family — where each model is weak

| Family | OWASP | qwen2.5 | Haiku 4.5 |
|---|---|---:|---:|
| indirect_prompt_injection | LLM01 | 50.0% | **0.0%** |
| jailbreak_carrier | LLM01 | 50.0% | **0.0%** |
| mcp_tool_poisoning | LLM01 | 50.0% | **0.0%** |
| mcp_rug_pull | LLM03 | 50.0% | **0.0%** |
| sensitive_info_disclosure | LLM02 | 50.0% | **0.0%** |
| mcp_tool_shadowing | LLM03 | 50.0% | 50.0% |
| scope_violation | LLM03 | 25.0% | **50.0%** |
| excessive_agency | LLM03 | 0.0% | **33.3%** |

**What the spread says** (this is why it's a benchmark, not a demo):
- **Haiku shrugs off everything qwen falls for** — indirect injection (incl. the
  AgentDojo `important_instructions` template that owns qwen), jailbreak carriers,
  tool-poisoning, rug-pull, and secret-disclosure all drop to **0%**. A far
  better-aligned model.
- **But Haiku is _more_ vulnerable where it counts for agents:** it complies with
  **scope violations** (a support bot asked to write code / answer off-topic / swap
  persona — 50%) and takes **excessive-agency** actions (33%). qwen's weakness is
  injection/exfiltration; Haiku's is *agency and staying in role.* One ASR number
  would have hidden that completely.
- Resistance shows up mostly as `clean` (payload silently ignored, benign task done)
  rather than explicit `refusal` — an honest, measurable behaviour difference.

## Defence Delta — one guardrail, measured on both models

The money metric: the same suite with one guardrail enabled — a heuristic **I/O
content filter** that sanitises inbound tool descriptions + outputs, enforces a
**least-privilege egress allow-list** on `send_email`, and redacts leaked secrets
(`src/agent_probe/guard/filter.py`).

| Target | ASR baseline | ASR guarded | Δ |
|---|---:|---:|---:|
| qwen2.5:7b | **41.9%** | **6.5%** | **−35.4 pts** |
| Claude Haiku 4.5 | **12.9%** | **3.2%** | **−9.7 pts** |

**Read this honestly** (it's a measurement tool, so the caveats matter):
- The guardrail is built to stop **exfiltration** (egress allow-list + injection
  screening). It does that well — which is why qwen's injection-heavy ASR collapses.
- **It does _not_ reach 0%, and that's the point:** what survives on *both* models is
  **scope violation** — an agent coerced off its role. An exfil guardrail has no
  opinion about a support bot answering trivia. **Different failure classes need
  different defences;** the dashboard shows the surviving red cells plainly.
- 0% is never claimed. This is a fixed, non-adaptive suite — an *adaptive* attacker
  (routing through an allow-listed channel, or avoiding the signatures) is the open
  problem, parked in [`BACKLOG.md`](BACKLOG.md).

> Targets are **local/synthetic** (qwen is free+offline; the Haiku run cost a few
> cents). Every attack is a readable YAML in [`attacks/gold/`](attacks/gold/) with a
> verified ATLAS id ([`docs/owasp-atlas-mapping.md`](docs/owasp-atlas-mapping.md)).
> OpenAI/DeepSeek targets remain deferred ([`BACKLOG.md`](BACKLOG.md)). Reproduce:
> `agent-probe run evals/gold.yaml --provider local --guard`, then
> `agent-probe delta <baseline>.jsonl <guarded>.jsonl`.
<!-- HERO-RESULTS:END -->

## Quickstart (dev)

```bash
uv sync --extra dev                                   # install
uv run agent-probe --help                             # see the command surface
uv run pytest                                         # run the tests (41)

uv run agent-probe list --owasp LLM03                 # browse the attack catalog
uv run agent-probe run evals/gold.yaml --provider local            # gold suite, free local qwen
uv run agent-probe run evals/gold.yaml --provider local --guard    # guarded config
uv run agent-probe run evals/gold.yaml --provider anthropic --model claude-haiku-4-5  # cloud target
uv run agent-probe delta <baseline>.jsonl <guarded>.jsonl          # Defence Delta table
uv run python dashboard/build.py                      # rebuild the dashboard from snapshots
```

The local target uses [Ollama](https://ollama.com) (`ollama pull qwen2.5:7b-instruct-q4_K_M`) —
free, offline, and the default surface for attack iteration. Copy `.env.example`
to `.env` and add `ANTHROPIC_API_KEY` to run against a Claude target. (OpenAI/DeepSeek
targets are deferred — see [`BACKLOG.md`](BACKLOG.md).)

## Responsible use

agent-probe is a **defensive** security-testing tool for **authorized** use only.
Targets are **synthetic agents we control** — a local model, or a cloud model called
through our own API key — with synthetic tools and data. It does **not** attack
third-party or production systems, accounts, or real data. It maps findings to public
taxonomies (OWASP LLM Top 10, MITRE ATLAS) and does not publish novel weaponization.
_(Expanded in Phase 5.)_

## License

MIT
