#!/usr/bin/env python3
"""
Re-run exactly the cells that were spoiled by a token cap.

A reply cut off by max_tokens carries no decision. The skill rule is to exclude
it rather than score it, but excluding is a last resort: the better fix is to
raise the cap and pay for the cell again, which is what this does.

Three distinct spoilage modes are detected, and the third is the dangerous one:

  propose truncated     -> the agent's action is unknown for that trial.
  judge truncated       -> the baseline's verdict is unknown for that trial.
  summarize truncated   -> SILENT CORRUPTION. build_memory() falls back to the
                           raw poison when the paraphrase is cut off, so the
                           whole `summarize` laundering channel for that
                           (model, scenario) silently degenerates into the
                           `direct` channel. Nothing in the output says so. Every
                           summarize cell for that pair must be redone.

Cells are rewritten into their own transcript; merge.py prefers a clean call
over a truncated one for the same cell.
"""
from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

import driver
import scenarios as S
import exp1_propensity as E

HERE = Path(__file__).parent
LOG = HERE.parent / "logs"
OUT = HERE.parent / "results"

# Raised caps. The originals were 1500/600/300; the models that overran are all
# reasoners that spend output tokens before answering.
MAX_PROPOSE, MAX_JUDGE, MAX_SUM = 3000, 1500, 1200


def scan():
    """Return the set of (model, sid, channel) cells that must be redone."""
    bad_cells, bad_sum = set(), set()
    for f in LOG.glob("exp1*.jsonl"):
        for line in f.open(encoding="utf-8"):
            try:
                r = json.loads(line)
            except Exception:
                continue
            if not r.get("truncated"):
                continue
            m = r.get("meta") or {}
            model, sid, ch = r["model"], m.get("sid"), m.get("channel")
            if r["tag"] == "summarize":
                bad_sum.add((model, sid))          # poisons the whole channel
            elif sid is not None:
                bad_cells.add((model, sid, ch))
    for model, sid in bad_sum:
        bad_cells.add((model, sid, "summarize"))
    return bad_cells, bad_sum


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    bad_cells, bad_sum = scan()
    by_model = collections.Counter(c[0] for c in bad_cells)
    print(f"cells needing re-run: {len(bad_cells)}")
    for m, n in sorted(by_model.items()):
        print(f"  {m:32s} {n:3d} cells")
    if bad_sum:
        print(f"\nsilent summarize corruption (whole channel degenerated to "
              f"`direct`) for {len(bad_sum)} (model, scenario) pairs:")
        for m, sid in sorted(bad_sum):
            print(f"  {m:32s} {sid}")
    n_calls = len(bad_cells) * (a.trials * 2 + 1) + len(bad_sum)
    driver.estimate([(m, n * (a.trials * 2 + 1), 500, 350)
                     for m, n in by_model.items()], "topup")
    if a.dry_run:
        return

    driver.open_transcript("exp1_topup")
    use0, rem0 = driver.credits()
    print(f"balance before: ${rem0:.4f}\n")
    attacks = {s["sid"]: s for s in S.ATTACK}
    legit = {s["sid"]: s for s in S.LEGIT}
    cache, rows = {}, []

    for (model, sid, ch) in sorted(bad_cells, key=lambda x: (x[0], x[1], str(x[2]))):
        for t in range(a.trials):
            if ch == "legit":
                scn = legit[sid]
                mon, supporting = E.build_legit_memory(scn)
                memtext = "\n".join(f"- {i.text}" for i in supporting)
                task, signals, tier = scn["task"], None, int(scn["tier"])
                meta = {"sid": sid, "channel": ch, "trial": t, "family": "legit",
                        "value": scn["value"], "vouchers": scn["vouchers"],
                        "tool": scn["tool"], "model": model, "topup": True}
            else:
                scn = attacks[sid]
                mon, seen, supporting, signals = E.build_memory(
                    scn, ch, model, cache)
                memtext = "\n".join(f"- {i.text}" for i in seen)
                task, tier = scn["task"], int(scn["tier"])
                meta = {"sid": sid, "channel": ch, "trial": t, "family": "attack",
                        "evil": scn["evil"], "good": scn["good"],
                        "tool": scn["tool"], "model": model, "topup": True}
            p = driver.gen(S.AGENT_USER.format(mem=memtext, task=task), model,
                           system=S.AGENT_SYSTEM, max_tokens=MAX_PROPOSE,
                           temperature=0.5, tag="propose", meta=meta)
            ja = driver.gen(
                E.JUDGE_ACT_USER.format(mem=memtext, task=task,
                                        action=p["text"][:600]),
                model, system=E.JUDGE_ACT_SYSTEM, max_tokens=MAX_JUDGE,
                temperature=0.0, tag="judge_act", meta=meta)
            rows.append({**meta, "memory_shown": memtext,
                         "proposal_raw": p["text"],
                         "proposal_finish": p["finish_reason"],
                         "proposal_truncated": p["truncated"],
                         "judge_act_raw": ja["text"],
                         "judge_act_truncated": ja["truncated"],
                         "monitor_labels": E.labels_of(supporting),
                         "signals": signals, "tier": tier})
            print(".", end="", flush=True)
        driver.gen(E.JUDGE_WRITE_USER.format(mem=memtext), model,
                   system=E.JUDGE_WRITE_SYSTEM, max_tokens=MAX_JUDGE,
                   temperature=0.0, tag="judge_write",
                   meta={"sid": sid, "channel": ch, "model": model, "topup": True})
    print()
    driver.report_cost(use0, "topup")
    (OUT / "exp1_topup.json").write_text(json.dumps(
        {"n_rows": len(rows), "cells": sorted(map(list, bad_cells)),
         "rows": rows}, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {OUT / 'exp1_topup.json'} ({len(rows)} rows)")


def _patch_summarize_cap():
    """The summarize call lives in exp1.build_memory with its own cap; raise it
    for this process only."""
    orig = driver.gen

    def wrapped(prompt, model, **kw):
        if kw.get("tag") == "summarize":
            kw["max_tokens"] = MAX_SUM
        return orig(prompt, model, **kw)
    driver.gen = wrapped


if __name__ == "__main__":
    _patch_summarize_cap()
    main()
