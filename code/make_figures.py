#!/usr/bin/env python3
"""
Render MEM-INV-Bench data figures from REAL results (results*.json) to vector PDFs
under ../paper/figures/. Data figures come from measured data, never an image
generator. Run after the eval suite.
"""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from stats import wilson, pooled, EXCLUDE

HERE = Path(__file__).parent
FIG = HERE.parent / "paper" / "figures"
FIG.mkdir(parents=True, exist_ok=True)

plt.rcParams.update({
    "font.size": 9, "axes.spines.top": False, "axes.spines.right": False,
    "figure.dpi": 150, "savefig.bbox": "tight", "axes.grid": True,
    "grid.alpha": 0.25, "grid.linewidth": 0.5,
})
COLORS = {"none": "#666666", "prob_detect": "#E69F00", "lineage": "#56B4E9",
          "temporal_auth": "#009E73"}
DEFS = ["none", "prob_detect", "lineage", "temporal_auth"]
SHORT = {"openai/gpt-5-chat": "gpt-5", "openai/gpt-4o-mini": "4o-mini",
         "anthropic/claude-opus-4.1": "opus-4.1",
         "anthropic/claude-sonnet-4.5": "sonnet-4.5", "google/gemini-2.5-flash": "gemini-2.5",
         "meta-llama/llama-4-maverick": "llama-4", "deepseek/deepseek-chat": "deepseek",
         "qwen/qwen3-235b-a22b": "qwen3"}


def load(name):
    p = HERE / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def fig_pooled():
    """MAIN figure: pooled consequential-ASR by defense for each trigger type, with
    Wilson 95% CIs. Computed from raw counts."""
    d = load("results.json")
    if not d:
        return
    res = d["results"]
    trigs = [("static", "cons_static"), ("adaptive", "cons_adapt"), ("whitebox", "cons_white")]
    fig, ax = plt.subplots(figsize=(5.0, 2.9))
    w = 0.2
    x = range(len(trigs))
    for i, dn in enumerate(DEFS):
        ys, los, his = [], [], []
        for _, b in trigs:
            h, n = pooled(res, dn, [b])
            p, lo, hi = wilson(h, n) if n else (0, 0, 0)
            ys.append(p); los.append(p - lo); his.append(hi - p)
        ax.bar([xi + (i - 1.5) * w for xi in x], ys, w, yerr=[los, his],
               capsize=2, label=dn.replace("_", " "), color=COLORS[dn],
               error_kw={"elinewidth": 0.7})
    ax.set_xticks(list(x)); ax.set_xticklabels([t for t, _ in trigs])
    ax.set_ylabel("consequential-ASR (%)")
    ax.set_ylim(0, 100)
    ax.set_xlabel("trigger type")
    ax.legend(fontsize=7, frameon=False, ncol=2)
    fig.savefig(FIG / "fig_pooled_asr.pdf")
    plt.close(fig)
    print("wrote fig_pooled_asr.pdf")


def fig_crossmodel():
    d = load("results.json")
    if not d:
        return
    res = d["results"]
    models = [m for m in res if m not in EXCLUDE]
    fig, ax = plt.subplots(figsize=(7.2, 2.8))
    x = range(len(models))
    w = 0.2
    for i, dn in enumerate(DEFS):
        vals = [res[m][dn]["cons_adapt_asr"] for m in models]
        ax.bar([xi + (i - 1.5) * w for xi in x], vals, w,
               label=dn.replace("_", " "), color=COLORS[dn])
    ax.set_xticks(list(x))
    ax.set_xticklabels([SHORT.get(m, m) for m in models], rotation=30, ha="right")
    ax.set_ylabel("adaptive consequential-ASR (%)")
    ax.set_ylim(0, 100)
    ax.legend(fontsize=7, frameon=False, ncol=4, loc="upper center")
    fig.savefig(FIG / "fig_crossmodel_asr.pdf")
    plt.close(fig)
    print("wrote fig_crossmodel_asr.pdf")


def fig_persistence():
    d = load("results_persistence.json")
    if not d:
        return
    curve = d["curve"]
    ns = sorted(int(k) for k in curve)
    none = [curve[str(n)]["none"] for n in ns]
    ours = [curve[str(n)]["temporal_auth"] for n in ns]
    fig, ax = plt.subplots(figsize=(3.4, 2.5))
    ax.plot(ns, none, "o-", color=COLORS["none"], label="none")
    ax.plot(ns, ours, "s-", color=COLORS["temporal_auth"], label="temporal_auth")
    ax.set_xlabel("intervening sessions $N$")
    ax.set_ylabel("consequential-ASR (%)")
    ax.set_ylim(-3, 100)
    ax.legend(frameon=False)
    fig.savefig(FIG / "fig_persistence.pdf")
    plt.close(fig)
    print("wrote fig_persistence.pdf")


def fig_ablation():
    d = load("results_ablation.json")
    if not d:
        return
    res = d["results"]
    models = [m for m in res if m not in EXCLUDE]
    conds = ["none", "temporal_auth", "ta_no_binding", "ta_no_elevation", "ta_no_log"]
    labels = ["none", "TMA", "$-$M1", "$-$M2", "$-$M3"]

    def avg(cond, key):
        return sum(res[m][cond][key] for m in models) / len(models)

    asr = [avg(c, "cons_adapt_asr") for c in conds]
    util = [avg(c, "utility") for c in conds]
    x = range(len(conds))
    w = 0.38
    fig, ax = plt.subplots(figsize=(3.6, 2.6))
    ax.bar([xi - w / 2 for xi in x], asr, w, label="adapt-ASR", color="#D55E00")
    ax.bar([xi + w / 2 for xi in x], util, w, label="utility", color="#0072B2")
    ax.set_xticks(list(x)); ax.set_xticklabels(labels)
    ax.set_ylabel("% (mean over models)")
    ax.set_ylim(0, 100)
    ax.legend(frameon=False, fontsize=8)
    fig.savefig(FIG / "fig_ablation.pdf")
    plt.close(fig)
    print("wrote fig_ablation.pdf")


def fig_laundering():
    """Correspondence heatmap: defense x channel -> attacker ASR, pooled over the 8
    reliable models, computed from the unified benchmark's per-model cells."""
    d = load("results_unified.json")
    if not d:
        return
    pm = d["per_model"]
    kept = [m for m in pm if m not in EXCLUDE]
    defs = ["none", "trust_score", "lineage", "capability_ifc", "tma_nm"]
    chans = ["direct", "summarize", "tool_echo", "corroborate"]

    def cell(de, c):
        h = sum(pm[m][de][c][0] for m in kept); n = sum(pm[m][de][c][1] for m in kept)
        return 100.0 * h / n if n else 0.0
    grid = [[cell(de, c) for c in chans] for de in defs]
    fig, ax = plt.subplots(figsize=(5.0, 3.0))
    im = ax.imshow(grid, cmap="Reds", vmin=0, vmax=100, aspect="auto")
    ax.set_xticks(range(len(chans))); ax.set_xticklabels(chans, rotation=20, ha="right")
    ax.set_yticks(range(len(defs))); ax.set_yticklabels(defs)
    for i in range(len(defs)):
        for j in range(len(chans)):
            v = grid[i][j]
            ax.text(j, i, f"{v:.0f}", ha="center", va="center",
                    color="white" if v > 55 else "black", fontsize=8)
    ax.set_title("attacker-action ASR (%): defense x laundering channel")
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    fig.savefig(FIG / "fig_laundering.pdf")
    plt.close(fig)
    print("wrote fig_laundering.pdf")


def fig_unified():
    """Primary figure: pooled ASR/utility by defense with Wilson CIs, from the unified
    benchmark (8 reliable models). Bars: direct-ASR, laundering-ASR, legit-utility."""
    d = load("results_unified.json")
    if not d:
        return
    s = d["pooled"]
    defs = ["none", "trust_score", "lineage", "capability_ifc", "tma_nm"]
    metrics = [("direct", "direct-ASR"), ("laundering", "laundering-ASR"),
               ("legit_utility", "legit-utility")]
    fig, ax = plt.subplots(figsize=(6.0, 3.0))
    w = 0.15
    x = range(len(metrics))
    palette = ["#666666", "#E69F00", "#56B4E9", "#CC79A7", "#009E73"]
    for i, dn in enumerate(defs):
        ys = [s[dn][m][0] for m, _ in metrics]
        los = [max(0.0, s[dn][m][0] - s[dn][m][1]) for m, _ in metrics]
        his = [max(0.0, s[dn][m][2] - s[dn][m][0]) for m, _ in metrics]
        ax.bar([xi + (i - 2) * w for xi in x], ys, w, yerr=[los, his], capsize=2,
               label=dn.replace("_", " "), color=palette[i], error_kw={"elinewidth": 0.7})
    ax.set_xticks(list(x)); ax.set_xticklabels([lbl for _, lbl in metrics])
    ax.set_ylabel("%  (pooled, 8 models)")
    ax.set_ylim(0, 105)
    ax.legend(fontsize=7, frameon=False, ncol=3, loc="upper center")
    fig.savefig(FIG / "fig_unified.pdf")
    plt.close(fig)
    print("wrote fig_unified.pdf")


if __name__ == "__main__":
    fig_unified()
    fig_laundering()
    fig_pooled()
    fig_crossmodel()
    fig_persistence()
    fig_ablation()
    print("figures ->", FIG)
