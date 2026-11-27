"""Build the static dashboard: read every committed result snapshot, compute all
numbers through the real scoring code, and bake them into `dashboard/index.html`
via `dashboard/template.html`. No network, no backend — the page is self-contained.

Supports multiple targets (e.g. a local qwen and a cloud Haiku) so the dashboard
shows a per-model view plus a cross-model comparison. A target whose guarded
snapshot is missing still renders its baseline.

Run from the repo root:  uv run python dashboard/build.py
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from agent_probe.models import Outcome
from agent_probe.scoring import defence_delta, score, score_by_family, score_by_owasp
from agent_probe.store import read_results

ROOT = Path(__file__).resolve().parent.parent
R = ROOT / "evals/results"

# (label, baseline snapshot, guarded snapshot). Order = selector order.
TARGETS = [
    ("qwen2.5:7b (local)", R / "gold-qwen2.5-7b.jsonl", R / "gold-qwen2.5-7b-guarded.jsonl"),
    ("claude-haiku-4-5", R / "gold-haiku-4-5.jsonl", R / "gold-haiku-4-5-guarded.jsonl"),
]


def _metrics(rows) -> dict:
    m = score(rows)
    return {
        "asr": m.asr, "rr": m.rr, "clean": m.clean_completion_rate,
        "hijack": m.tool_hijack_rate, "harm": m.harm_weighted_asr,
        "n_scored": m.n_scored, "n_total": m.n_total,
        "successes": m.successes, "refusals": m.refusals,
        "cleans": m.clean_completions, "errors": m.n_error,
    }


def _outcomes(rows) -> dict:
    c = Counter(r.outcome.value for r in rows)
    return {o.value: c.get(o.value, 0) for o in Outcome}


def _families(base, guard) -> list[dict]:
    fam_base = {g.group: g for g in score_by_family(base)}
    fam_guard = {g.group: g for g in score_by_family(guard)} if guard else {}
    out = []
    for fam in sorted(fam_base):
        fb = [r for r in base if r.family == fam]
        out.append({
            "family": fam,
            "owasp": fb[0].owasp if fb else "",
            "n": fam_base[fam].n_scored,
            "base_asr": fam_base[fam].asr,
            "guard_asr": fam_guard[fam].asr if fam in fam_guard else None,
            "base_outcomes": _outcomes(fb),
        })
    return out


def _probes(base, guard) -> list[dict]:
    base_by = {r.attack_id: r for r in base}
    guard_by = {r.attack_id: r for r in (guard or [])}
    out = []
    for aid in sorted(base_by):
        b = base_by[aid]
        g = guard_by.get(aid)
        out.append({
            "id": aid, "family": b.family, "owasp": b.owasp, "atlas": b.atlas,
            "severity": b.severity,
            "base": {"outcome": b.outcome.value, "hijack": b.tool_hijack,
                     "latency": b.latency_ms, "detail": b.judge_detail, "trace": b.trace},
            "guard": None if g is None else {
                "outcome": g.outcome.value, "hijack": g.tool_hijack,
                "guard_blocked": g.guard_blocked, "latency": g.latency_ms,
                "detail": g.judge_detail, "trace": g.trace},
        })
    return out


def _target_block(base, guard) -> dict:
    block = {
        "model": base[0].model if base else "?",
        "scoreboard": {"baseline": _metrics(base), "guarded": _metrics(guard) if guard else None},
        "families": _families(base, guard),
        "owasp": [{"owasp": g.group, "n": g.n_scored, "base_asr": g.asr}
                  for g in score_by_owasp(base)],
        "probes": _probes(base, guard),
    }
    if guard:
        delta = [d.model_dump() for d in defence_delta(base, guard)]
        overall = next(d for d in delta if d["group"] == "overall")
        block["scoreboard"]["delta_pts"] = round(
            (overall["asr_baseline"] - overall["asr_guarded"]) * 100, 1)
        block["scoreboard"]["guard_pass_rate"] = overall["guard_pass_rate"]
        block["scoreboard"]["asr_behind_filter"] = overall["asr_behind_filter"]
        block["delta"] = delta
    return block


def main() -> None:
    targets: dict[str, dict] = {}
    labels: list[str] = []
    for label, base_path, guard_path in TARGETS:
        if not base_path.exists():
            print(f"skip {label}: no baseline at {base_path.name}")
            continue
        base = read_results(base_path)
        guard = read_results(guard_path) if guard_path.exists() else None
        targets[label] = _target_block(base, guard)
        labels.append(label)

    # Cross-model: baseline ASR per family across targets.
    fam_ids = sorted({f["family"] for t in targets.values() for f in t["families"]})
    cross_fam = []
    for fam in fam_ids:
        row = {"family": fam, "owasp": "", "asr": {}}
        for label in labels:
            f = next((x for x in targets[label]["families"] if x["family"] == fam), None)
            if f:
                row["owasp"] = f["owasp"]
                row["asr"][label] = f["base_asr"]
        cross_fam.append(row)
    cross_overall = {
        label: {
            "base_asr": targets[label]["scoreboard"]["baseline"]["asr"],
            "guard_asr": (targets[label]["scoreboard"]["guarded"] or {}).get("asr")
            if targets[label]["scoreboard"]["guarded"] else None,
        }
        for label in labels
    }

    n = targets[labels[0]]["scoreboard"]["baseline"]["n_total"] if labels else 0
    data = {
        "meta": {"n": n, "labels": labels},
        "targets": targets,
        "cross": {"families": cross_fam, "overall": cross_overall},
    }

    template = (Path(__file__).parent / "template.html").read_text(encoding="utf-8")
    html = template.replace("/*__DATA__*/", json.dumps(data, ensure_ascii=False))
    out = Path(__file__).parent / "index.html"
    out.write_text(html, encoding="utf-8")
    print(f"built {out}  ({len(html) // 1024} KB, targets: {', '.join(labels)})")


if __name__ == "__main__":
    main()
