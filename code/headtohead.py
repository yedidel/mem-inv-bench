#!/usr/bin/env python3
"""
Head-to-head evaluation: reproduce four *published* memory-poisoning pipelines as
drop-in scenarios and measure consequential-ASR under each defense, broken down per
pipeline, across all MODELS. One pass over the API (no double spend): scenarios are
grouped by their `_pipeline` tag and evaluate() is run per group.

  MemMorph              (2605.26154)  tool hijacking via disguised technical-fact records
  MemoryGraft           (2512.16962)  poisoned successful-experience retrieval
  Trojan Hippo          (2605.01970)  topic-triggered exfiltration via one untrusted call
  Hijacking Agent Memory(2605.29960)  conversational triggerable backdoor

Writes results_headtohead.json (per-pipeline + overall pooled) and the LaTeX table
../paper/tables/tab_headtohead.tex. Numbers come straight from real OpenRouter calls.
"""
import argparse
import json
from pathlib import Path

import agent_bench
import llm
from stats import wilson

HERE = Path(__file__).parent
TAB = HERE.parent / "paper" / "tables"

DEFS = ["none", "prob_detect", "lineage", "temporal_auth"]
CONS = ["cons_static", "cons_adapt", "cons_white"]

# short tag -> (display label, prefix that identifies the pipeline in `_pipeline`)
PIPELINES = [
    ("MemMorph",     "MemMorph"),
    ("MemoryGraft",  "MemoryGraft"),
    ("Trojan Hippo", "Trojan Hippo"),
    ("Conv. Trojan", "Hijacking Agent Memory"),
]


def pool_group(res, defense, buckets):
    h = n = 0
    for m in res:
        raw = res[m][defense]["raw"]
        for b in buckets:
            h += raw[f"{b}_hit"]
            n += raw[f"{b}_n"]
    return h, n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="*", default=None)
    ap.add_argument("--trials", type=int, default=6)
    ap.add_argument("--scenarios", default="scenarios_headtohead.json")
    args = ap.parse_args()

    all_scn = json.loads((HERE / args.scenarios).read_text(encoding="utf-8"))
    models = args.models or llm.MODELS

    use0, rem0 = llm.credits()
    if rem0 is not None:
        print(f"OpenRouter balance before: ${rem0:.4f} (used ${use0:.4f})\n")

    out = {"models": models, "trials": args.trials, "pipelines": {}}
    for label, prefix in PIPELINES:
        group = [s for s in all_scn if s.get("_pipeline", "").startswith(prefix)]
        if not group:
            print(f"!! no scenarios for {label}")
            continue
        print(f"=== {label}: {len(group)} scenarios x {args.trials} trials ===")
        agent_bench.SCENARIOS = group
        res = agent_bench.evaluate(models, args.trials, defenses=DEFS)
        out["pipelines"][label] = res

    spent, rem1 = llm.report_cost(use0, "head-to-head")
    out["cost_usd"] = spent
    out["balance_remaining_usd"] = rem1
    (HERE / "results_headtohead.json").write_text(json.dumps(out, indent=2), encoding="utf-8")

    # ---- console summary + LaTeX table ----
    print("\nConsequential-ASR (all triggers, pooled over models), per pipeline:")
    hdr = f"{'Pipeline':<14}" + "".join(f"{d:>14}" for d in DEFS)
    print(hdr)
    rows = []
    grand = {d: [0, 0] for d in DEFS}
    util = {d: [0, 0] for d in DEFS}
    for label, _ in PIPELINES:
        res = out["pipelines"].get(label)
        if not res:
            continue
        cells = []
        line = f"{label:<14}"
        for d in DEFS:
            h, n = pool_group(res, d, CONS)
            grand[d][0] += h; grand[d][1] += n
            uh, un = pool_group(res, d, ["util"])
            util[d][0] += uh; util[d][1] += un
            p, lo, hi = wilson(h, n)
            line += f"{p:>9.1f}%({h}/{n})".rjust(14)
            bold = d == "temporal_auth"
            cells.append((f"\\bfseries " if bold else "") + f"{p:.0f}")
        print(line)
        rows.append(f"{label} & " + " & ".join(cells) + " \\\\")

    # grand pooled row
    gcells = []
    gline = f"{'ALL FOUR':<14}"
    for d in DEFS:
        h, n = grand[d]
        p, lo, hi = wilson(h, n)
        gline += f"{p:>9.1f}%({h}/{n})".rjust(14)
        bold = d == "temporal_auth"
        gcells.append((f"\\bfseries " if bold else "") + f"{p:.1f}")
    print(gline)
    rows.append("\\midrule")
    rows.append(f"\\textbf{{All four}} & " + " & ".join(gcells) + " \\\\")

    print("\nUtility (benign tasks, pooled over models), per defense:")
    for d in DEFS:
        h, n = util[d]
        p, lo, hi = wilson(h, n)
        print(f"  {d:<14} {p:5.1f}% [{lo:.1f},{hi:.1f}] ({h}/{n})")

    lines = ["\\begin{tabular}{lrrrr}", "\\toprule",
             "Published pipeline & none & prob\\_detect & lineage & \\bfseries TMA-NM \\\\",
             "\\midrule"] + rows + ["\\bottomrule", "\\end{tabular}"]
    TAB.mkdir(parents=True, exist_ok=True)
    (TAB / "tab_headtohead.tex").write_text("\n".join(lines) + "\n",
                                            encoding="utf-8", newline="\n")
    print("\nwrote", TAB / "tab_headtohead.tex")


if __name__ == "__main__":
    main()
