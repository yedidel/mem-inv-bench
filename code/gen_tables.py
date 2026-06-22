#!/usr/bin/env python3
"""
Generate COMPLETE LaTeX tabulars from REAL results into ../paper/tables/ so the paper's
numbers come straight from results*.json (no manual transcription). Each file is a
self-contained \\begin{tabular}...\\end{tabular} (robust to \\input), written with LF
newlines. \\input these inside a table float in tdsc.tex. Run after the eval suite.
"""
import json
from pathlib import Path

from stats import wilson, pooled

HERE = Path(__file__).parent
TAB = HERE.parent / "paper" / "tables"
TAB.mkdir(parents=True, exist_ok=True)

SHORT = {"openai/gpt-5-chat": "gpt-5-chat", "openai/gpt-4o-mini": "gpt-4o-mini",
         "anthropic/claude-opus-4.1": "claude-opus-4.1",
         "anthropic/claude-sonnet-4.5": "claude-sonnet-4.5", "google/gemini-2.5-flash": "gemini-2.5-flash",
         "meta-llama/llama-4-maverick": "llama-4-maverick", "deepseek/deepseek-chat": "deepseek-chat",
         "qwen/qwen3-235b-a22b": "qwen3-235b"}
DEFS = ["none", "prob_detect", "lineage", "temporal_auth"]
EXCLUDE = set()   # all reported models are reliable (0% empty under the guard)


def _models(res):
    return [m for m in res if m not in EXCLUDE]


def load(name):
    p = HERE / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def esc(s):
    return s.replace("_", "\\_")


def write(name, colspec, header, body_rows):
    lines = [f"\\begin{{tabular}}{{{colspec}}}", "\\toprule", header + " \\\\", "\\midrule"]
    lines += body_rows
    lines += ["\\bottomrule", "\\end{tabular}"]
    (TAB / name).write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print("wrote", name)


def cross_table():
    d = load("results.json")
    if not d:
        return
    res = d["results"]
    rows = []
    models = _models(res)
    for mi, m in enumerate(models):
        for d_ in DEFS:
            r = res[m][d_]
            cells = (f"{r['cons_static_asr']:.0f} & {r['cons_adapt_asr']:.0f} & "
                     f"{r['cons_white_asr']:.0f} & {r['utility']:.0f}")
            name = esc(SHORT.get(m, m)) if d_ == DEFS[0] else ""
            bold = "\\bfseries " if d_ == "temporal_auth" else ""
            rows.append(f"{name} & {bold}{esc(d_)} & {bold}{cells} \\\\")
        if mi != len(models) - 1:
            rows.append("\\midrule")
    write("tab_cross.tex", "llrrrr",
          "Model & Defense & cons-st & cons-ad & cons-wb & util", rows)


def pooled_table():
    d = load("results.json")
    if not d:
        return
    res = d["results"]
    rows = []
    for d_ in DEFS:
        row = [esc(d_)]
        for buckets in (["cons_static"], ["cons_adapt"], ["cons_white"],
                        ["cons_static", "cons_adapt", "cons_white"], ["util"]):
            h, n = pooled(res, d_, buckets)
            p, lo, hi = wilson(h, n) if n else (0, 0, 0)
            row.append(f"{p:.1f} [{lo:.1f},{hi:.1f}]")
        rows.append(" & ".join(row) + " \\\\")
    write("tab_pooled.tex", "llllll",
          "Defense & static & adaptive & whitebox & all & utility", rows)


def ablation_table():
    d = load("results_ablation.json")
    if not d:
        return
    res = d["results"]
    models = _models(res)
    conds = [("none", "none"), ("temporal_auth", "TMA-NM (full)"),
             ("ta_no_binding", "$-$origin binding"), ("ta_no_elevation", "$-$elevation"),
             ("ta_no_log", "$-$verdict log")]

    def avg(c, k):
        return sum(res[m][c][k] for m in models) / len(models)

    rows = []
    for c, lab in conds:
        rows.append(f"{lab} & {avg(c,'cons_static_asr'):.0f} & {avg(c,'cons_adapt_asr'):.0f} "
                    f"& {avg(c,'cons_white_asr'):.0f} & {avg(c,'utility'):.0f} \\\\")
    write("tab_ablation.tex", "lrrrr",
          "Condition & cons-st & cons-ad & cons-wb & utility", rows)


def unified_table():
    d = load("results_unified.json")
    if not d:
        return
    s = d["pooled"]
    order = [("none", "none"), ("trust\\_score", "trust_score"),
             ("lineage", "lineage"), ("capability\\_ifc", "capability_ifc"),
             ("\\bfseries TMA-NM", "tma_nm")]
    rows = []
    for label, k in order:
        v = s[k]
        b = "\\bfseries " if k == "tma_nm" else ""
        rows.append(f"{label} & {b}{v['direct'][0]:.0f} & {b}{v['laundering'][0]:.0f} & "
                    f"{b}{v['legit_utility'][0]:.0f} & {b}{v['legit_uncorr_autoauth'][0]:.0f} \\\\")
    write("tab_unified.tex", "lrrrr",
          "Defense & direct-ASR & laund.-ASR & legit-util. & uncorr-auto", rows)


if __name__ == "__main__":
    unified_table()
    cross_table()
    pooled_table()
    ablation_table()
    print("tables ->", TAB)
