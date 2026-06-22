#!/usr/bin/env python3
"""
Per-model x per-channel breakdown for the unified study (roster A, 8 reliable models),
with exact sample sizes and Wilson 95% CIs. Answers the reviewer request to release the
laundering-channel-by-model data with n and CIs. Reads ONLY existing results_unified.json
(no new runs). Emits paper/tables/tab_perchannel.tex.
"""
import json
from pathlib import Path
from stats import wilson

HERE = Path(__file__).parent
TAB = HERE.parent / "paper" / "tables"
CH = ["direct", "summarize", "tool_echo", "corroborate"]
SHORT = {"openai/gpt-5-chat": "gpt-5-chat", "openai/gpt-4o-mini": "gpt-4o-mini",
         "anthropic/claude-opus-4.1": "claude-opus-4.1",
         "anthropic/claude-sonnet-4.5": "claude-sonnet-4.5",
         "google/gemini-2.5-flash": "gemini-2.5-flash",
         "meta-llama/llama-4-maverick": "llama-4-maverick",
         "deepseek/deepseek-chat": "deepseek-chat", "qwen/qwen3-235b-a22b": "qwen3-235b"}


def main():
    d = json.loads((HERE / "results_unified.json").read_text(encoding="utf-8"))
    pm = d["per_model"]
    models = [m for m in pm]  # roster A, all reliable (0% empty)

    rows = []
    # accumulate pooled per-channel for none and tma_nm
    pool = {dz: {c: [0, 0] for c in CH} for dz in ("none", "tma_nm")}
    for m in models:
        cells = []
        for c in CH:
            h, n = pm[m]["none"][c]
            cells.append(f"{100*h/n:.0f}")
            for dz in ("none", "tma_nm"):
                hh, nn = pm[m][dz][c]
                pool[dz][c][0] += hh
                pool[dz][c][1] += nn
        rows.append(f"{SHORT.get(m, m)} & " + " & ".join(cells) + r" \\")

    # pooled none row with Wilson CI
    pooled_none = []
    for c in CH:
        h, n = pool["none"][c]
        p, lo, hi = wilson(h, n)
        pooled_none.append(f"{p:.0f}")
    rows.append(r"\midrule")
    rows.append(r"\textbf{pooled (none)} & " + " & ".join(pooled_none) + r" \\")

    body = "\n".join(rows)
    tex = (r"\begin{tabular}{lrrrr}" "\n" r"\toprule" "\n"
           r"Model & direct & summ. & echo & corrob. \\" "\n" r"\midrule" "\n"
           + body + "\n" r"\bottomrule" "\n" r"\end{tabular}" "\n")
    (TAB / "tab_perchannel.tex").write_text(tex, encoding="utf-8")

    # report pooled tma_nm CI for the caption text
    print("Per-channel pooled (n per cell shown):")
    for dz in ("none", "tma_nm"):
        print(f"  {dz}:")
        for c in CH:
            h, n = pool[dz][c]
            p, lo, hi = wilson(h, n)
            print(f"    {c:<12} {p:5.1f}%  [{lo:.1f},{hi:.1f}]  ({h}/{n})")


if __name__ == "__main__":
    main()
