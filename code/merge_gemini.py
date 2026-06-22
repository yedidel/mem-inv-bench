#!/usr/bin/env python3
"""Merge a clean single-model re-run into the full unified results, recompute pooled+CI."""
import json
from pathlib import Path
from stats import wilson
from laundering import DEFENSES, CHANNELS

HERE = Path(__file__).parent
FULL = json.loads((HERE / "results_unified_full.json").read_text(encoding="utf-8"))
NEW = json.loads((HERE / "results_unified.json").read_text(encoding="utf-8"))
M = "google/gemini-2.5-pro"
cols = CHANNELS + ["legit"]

FULL["per_model"][M] = NEW["per_model"][M]          # replace gemini with clean run
pm = FULL["per_model"]
kept = FULL.get("kept", list(pm))


def pool(defense, chans):
    h = n = 0
    for m in kept:
        for c in chans:
            h += pm[m][defense][c][0]; n += pm[m][defense][c][1]
    return h, n


laund = ["summarize", "tool_echo", "corroborate"]
summary = {}
for d in DEFENSES:
    dh, dn = pool(d, ["direct"]); lh, ln = pool(d, laund); uh, un = pool(d, ["legit"])
    summary[d] = {"direct": wilson(dh, dn), "laundering": wilson(lh, ln),
                  "legit_utility": wilson(uh, un)}
FULL["pooled"] = summary
FULL["note"] = "gemini-2.5-pro re-run merged to clear 4.4% empty-rate"
(HERE / "results_unified.json").write_text(json.dumps(FULL, indent=2), encoding="utf-8")

print("merged. pooled (direct / laundering / legit-utility):")
for d in DEFENSES:
    s = summary[d]
    print(f"  {d:<15} {s['direct'][0]:>5.1f} [{s['direct'][1]:.0f},{s['direct'][2]:.0f}]"
          f"  {s['laundering'][0]:>5.1f} [{s['laundering'][1]:.0f},{s['laundering'][2]:.0f}]"
          f"  {s['legit_utility'][0]:>5.1f} [{s['legit_utility'][1]:.0f},{s['legit_utility'][2]:.0f}]")
