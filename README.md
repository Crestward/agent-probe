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

## Status

| Phase | What | State |
|---|---|---|
| 0 | Foundation & scaffolding | ✅ done |
| 1 | Vertical slice (one real attack → one real number) | ✅ done |
| 2 | Breadth: 5 attack families, published results table | ✅ done |
| 3 | Defence Delta + cross-model (Claude / GPT / DeepSeek) | ⬜ |
| 4 | CI gating, hardened judge, live dashboard | ⬜ |
| 5 | Polish, writeup & OSS contribution | ⬜ |

<!-- HERO-RESULTS:START -->
## Results — `qwen2.5:7b-instruct-q4_K_M` (local target)

27 curated attacks across all 5 families and 10 channels, scored end-to-end. The
headline is not one scary number — it's the **spread**: a research-backed technique
lands across every channel while naive payloads are ignored, and the agent holds
firm on system-prompt extraction and excessive-agency bait. _Defence is a number,
and the number moves with technique._

| Metric | Value |
|---|---|
| **ASR** (attack success rate) | **48.1%** |
| Refusal rate | 3.7% |
| Clean-completion rate | 48.1% |
| Tool-hijack rate | 40.7% |
| Harm-weighted ASR | 51.4% |
| Scored / total | 27 / 27 |

**By OWASP LLM Top-10 (2026):**

| OWASP | n | ASR | RR | Hijack |
|---|---:|---:|---:|---:|
| LLM01 Prompt Injection | 14 | 57.1% | 0.0% | 57.1% |
| LLM02 Sensitive Info Disclosure | 4 | 50.0% | 0.0% | 0.0% |
| LLM03 Excessive Agency | 9 | 33.3% | 11.1% | 33.3% |

**By attack family:**

| Family | n | ASR | RR | Hijack |
|---|---:|---:|---:|---:|
| indirect_prompt_injection | 10 | 60.0% | 0.0% | 60.0% |
| jailbreak_carrier | 4 | 50.0% | 0.0% | 50.0% |
| mcp_tool_poisoning | 2 | 50.0% | 0.0% | 50.0% |
| mcp_tool_shadowing | 2 | 50.0% | 0.0% | 50.0% |
| mcp_rug_pull | 2 | 50.0% | 50.0% | 50.0% |
| sensitive_info_disclosure | 4 | 50.0% | 0.0% | 0.0% |
| excessive_agency | 3 | 0.0% | 0.0% | 0.0% |

**What the spread says** (why this is a benchmark, not a demo):
- The AgentDojo **`important_instructions`** template (user-impersonation + prerequisite framing) succeeded on **every channel** — email, document, CRM field, support ticket, web page. Naive "SYSTEM: ignore instructions" banners were mostly **ignored** (scored `clean`). *Framing beats the model's instruction hierarchy; payload delivery alone does not.*
- **MCP-specific attacks land:** tool-description poisoning, tool-shadowing (a tool that's never called reprograms a trusted one), and a **rug-pull** (clean at approval, malicious on a later call) all hijacked the agent when framed well.
- The model **held** where it should: it never leaked its **system-prompt canary**, and it refused to take irreversible **excessive-agency** actions (0% ASR) — asking for confirmation instead of over-reaching.
- Resistance shows up as `clean` (payload ignored, benign task done), not `refusal` — an interesting, honest finding: this model *silently declines* injected instructions far more than it *explicitly* refuses.

> Target is a **local, synthetic** agent (free, offline, no third-party systems). Every attack is a readable YAML in [`attacks/gold/`](attacks/gold/) with a verified ATLAS id ([`docs/owasp-atlas-mapping.md`](docs/owasp-atlas-mapping.md)). Cross-model comparison (Claude vs GPT vs DeepSeek) and the guardrail **Defence Delta** land in Phase 3.
<!-- HERO-RESULTS:END -->

## Quickstart (dev)

```bash
uv sync --extra dev                                   # install
uv run agent-probe --help                             # see the command surface
uv run pytest                                         # run the tests (34)

uv run agent-probe list --owasp LLM03                 # browse the attack catalog
uv run agent-probe run evals/gold.yaml --provider local   # run the gold suite (free, local)
uv run agent-probe report evals/results/gold-qwen2.5-7b.jsonl --format md   # regenerate the table
```

The local target uses [Ollama](https://ollama.com) (`ollama pull qwen2.5:7b-instruct-q4_K_M`) —
free, offline, and the default surface for attack iteration. Copy `.env.example`
to `.env` and add an API key only to run against a cloud provider (Anthropic is the
default; OpenAI/DeepSeek land in Phase 3).

## Responsible use

agent-probe is a **defensive** security-testing tool for **authorized** use only.
All attack targets are **local and synthetic** — it does not attack third-party or
production systems. It maps findings to public taxonomies (OWASP LLM Top 10, MITRE
ATLAS) and does not publish novel weaponization. _(Expanded in Phase 5.)_

## License

MIT
