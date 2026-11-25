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
| 0 | Foundation & scaffolding | ✅ in progress |
| 1 | Vertical slice (one real attack → one real number) | ⬜ |
| 2 | Breadth: 5 attack families, published results table | ⬜ |
| 3 | Defence Delta + cross-model (Claude / GPT / DeepSeek) | ⬜ |
| 4 | CI gating, hardened judge, live dashboard | ⬜ |
| 5 | Polish, writeup & OSS contribution | ⬜ |

<!-- The hero results table will live here once Phase 2 lands. -->

## Quickstart (dev)

```bash
uv sync --extra dev        # install
uv run agent-probe --help  # see the command surface
uv run pytest              # run the smoke tests
```

Copy `.env.example` to `.env` and add your API key(s). Only the default provider's
key (Anthropic) is required; OpenAI and DeepSeek are needed only when selected.

## Responsible use

agent-probe is a **defensive** security-testing tool for **authorized** use only.
All attack targets are **local and synthetic** — it does not attack third-party or
production systems. It maps findings to public taxonomies (OWASP LLM Top 10, MITRE
ATLAS) and does not publish novel weaponization. _(Expanded in Phase 5.)_

## License

MIT
