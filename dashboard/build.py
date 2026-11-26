"""Build the static dashboard: read the committed result snapshots, compute every
number, and bake them into `dashboard/index.html` by substituting the JSON into
`dashboard/template.html`. No network, no backend — the page is self-contained.

Run from the repo root:  uv run python dashboard/build.py
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from agent_probe.attacks.spec import load_catalog
from agent_probe.models import Outcome
from agent_probe.scoring import defence_delta, score, score_by_family, score_by_owasp
from agent_probe.store import read_results

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "evals/results/gold-qwen2.5-7b.jsonl"
GUARDED = ROOT / "evals/results/gold-qwen2.5-7b-guarded.jsonl"


def _metrics(rows) -> dict:
    m = score(rows)
    return {
        "asr": m.asr,
        "rr": m.rr,
        "clean": m.clean_completion_rate,
        "hijack": m.tool_hijack_rate,
        "harm": m.harm_weighted_asr,
        "n_scored": m.n_scored,
        "n_total": m.n_total,
        "successes": m.successes,
        "refusals": m.refusals,
        "cleans": m.clean_completions,
        "errors": m.n_error,
    }


def _outcomes(rows) -> dict:
    c = Counter(r.outcome.value for r in rows)
    return {o.value: c.get(o.value, 0) for o in Outcome}


def main() -> None:
    base = read_results(BASELINE)
    guard = read_results(GUARDED)
    techniques = {a.id: a.technique for a in load_catalog(str(ROOT / "attacks/gold"))}

    base_by_id = {r.attack_id: r for r in base}
    guard_by_id = {r.attack_id: r for r in guard}

    # Per-family rows with both configs' ASR and outcome mix.
    fam_base = {g.group: g for g in score_by_family(base)}
    fam_guard = {g.group: g for g in score_by_family(guard)}
    families = []
    for fam in sorted(fam_base):
        fb = [r for r in base if r.family == fam]
        fg = [r for r in guard if r.family == fam]
        families.append(
            {
                "family": fam,
                "owasp": fb[0].owasp if fb else "",
                "n": fam_base[fam].n_scored,
                "base_asr": fam_base[fam].asr,
                "guard_asr": fam_guard[fam].asr if fam in fam_guard else 0.0,
                "base_outcomes": _outcomes(fb),
                "guard_outcomes": _outcomes(fg),
            }
        )

    owasp = []
    ob = {g.group: g for g in score_by_owasp(base)}
    og = {g.group: g for g in score_by_owasp(guard)}
    for oid in sorted(ob):
        owasp.append(
            {
                "owasp": oid,
                "n": ob[oid].n_scored,
                "base_asr": ob[oid].asr,
                "guard_asr": og[oid].asr if oid in og else 0.0,
            }
        )

    delta = [d.model_dump() for d in defence_delta(base, guard)]

    probes = []
    for aid in sorted(base_by_id):
        b = base_by_id[aid]
        g = guard_by_id.get(aid)
        probes.append(
            {
                "id": aid,
                "family": b.family,
                "owasp": b.owasp,
                "atlas": b.atlas,
                "severity": b.severity,
                "technique": techniques.get(aid),
                "base": {
                    "outcome": b.outcome.value,
                    "hijack": b.tool_hijack,
                    "latency": b.latency_ms,
                    "detail": b.judge_detail,
                    "trace": b.trace,
                },
                "guard": None
                if g is None
                else {
                    "outcome": g.outcome.value,
                    "hijack": g.tool_hijack,
                    "guard_blocked": g.guard_blocked,
                    "latency": g.latency_ms,
                    "detail": g.judge_detail,
                    "trace": g.trace,
                },
            }
        )

    overall = next(d for d in delta if d["group"] == "overall")
    data = {
        "meta": {
            "model": base[0].model if base else "?",
            "provider": base[0].provider if base else "?",
            "n": len(base),
            "baseline_run": base[0].run_id if base else "?",
            "guarded_run": guard[0].run_id if guard else "?",
        },
        "scoreboard": {
            "baseline": _metrics(base),
            "guarded": _metrics(guard),
            "delta_pts": round((overall["asr_baseline"] - overall["asr_guarded"]) * 100, 1),
            "guard_pass_rate": overall["guard_pass_rate"],
            "asr_behind_filter": overall["asr_behind_filter"],
        },
        "families": families,
        "owasp": owasp,
        "delta": delta,
        "probes": probes,
    }

    template = (Path(__file__).parent / "template.html").read_text(encoding="utf-8")
    payload = json.dumps(data, ensure_ascii=False)
    html = template.replace("/*__DATA__*/", payload)
    out = Path(__file__).parent / "index.html"
    out.write_text(html, encoding="utf-8")
    print(f"built {out}  ({len(html) // 1024} KB, {len(probes)} probes)")


if __name__ == "__main__":
    main()
