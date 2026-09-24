#!/usr/bin/env python3
"""Re-run experiment 11's truncated cells at a higher token cap.

Thirteen of 768 replies hit the 1024-token limit and returned an empty body:
reasoning models that spent the whole budget before emitting an action. Those
carry no decision and are excluded, which is correct but not free. Eight of the
thirteen belong to one model, so leaving them out removes an eighth of that
model's cells and the remainder is no longer a random sample of the design.

Re-running only those cells, at a cap large enough that the reasoning fits, is
cheaper than re-running the experiment and is the same remedy used for the
propensity run. Rows land in a separate file and supersede the truncated ones by
cell key, so nothing already paid for is discarded and the original transcript
stays intact.
"""
from __future__ import annotations

import argparse
import json

import driver
from exp11_headtohead import (CONFIGS, SCENARIOS, TOOL_SCHEMA, USER, SYSTEM,
                              attacked_fields, build_memory, gate_verdict,
                              parse_action, _ckpt, _write)
from review11 import load, bucket


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", default="exp11_h2h")
    ap.add_argument("--out-id", default="exp11_topup")
    ap.add_argument("--max-tokens", type=int, default=4096)
    ap.add_argument("--estimate-only", action="store_true")
    args = ap.parse_args()

    rows = load(args.run_id)
    bad = [r for r in rows if r.get("truncated")]
    print(f"truncated cells to re-run: {len(bad)}")
    for r in bad:
        print(f"  {r['model']:28s} {r['sid']}/{r['style']}/t{r['trial']}")

    by_model = {}
    for r in bad:
        by_model[r["model"]] = by_model.get(r["model"], 0) + 1
    plan = [(m, n, 620, args.max_tokens) for m, n in by_model.items()]
    driver.estimate(plan, label=f"exp11 top-up at max_tokens={args.max_tokens}")
    if args.estimate_only:
        return

    done = set()
    p = _ckpt(args.out_id)
    if p.exists():
        for line in p.open(encoding="utf-8"):
            if line.strip():
                d = json.loads(line)
                done.add((d["model"], d["sid"], d["style"], d["trial"]))

    scn_by_sid = {s["sid"]: s for s in SCENARIOS}
    driver.open_transcript(args.out_id, append=True)
    for r in bad:
        key = (r["model"], r["sid"], r["style"], r["trial"])
        if key in done:
            continue
        scn = scn_by_sid[r["sid"]]
        mon, items, supporting = build_memory(scn, r["style"])
        mem = "\n".join(f"- {it.text}" for it in items)
        res = driver.gen(
            USER.format(mem=mem, schema=TOOL_SCHEMA[scn["tool"]], task=scn["task"]),
            r["model"], system=SYSTEM, max_tokens=args.max_tokens,
            temperature=0.4, tag="propose",
            meta={"sid": scn["sid"], "pipeline": scn["pipeline"],
                  "style": r["style"], "trial": r["trial"], "model": r["model"],
                  "topup": True})
        act = parse_action(res["text"])
        _write(args.out_id, {
            "model": r["model"], "sid": scn["sid"], "pipeline": scn["pipeline"],
            "paper": scn["paper"], "attack_class": scn["attack_class"],
            "style": r["style"], "trial": r["trial"],
            "tool_expected": scn["tool"],
            "attacker": scn["attacker"], "benign": scn["benign"],
            "raw": res["text"], "finish": res["finish_reason"],
            "truncated": res["truncated"], "ok": res["ok"],
            "action": act, "topup": True,
            "attacked_fields": attacked_fields(scn),
            "gate": {c: gate_verdict(*build_memory(scn, r["style"], c)[0::2],
                                     act, attacked_fields(scn)) for c in CONFIGS},
            "gate_allfields": {
                c: gate_verdict(*build_memory(scn, r["style"], c)[0::2], act)
                for c in CONFIGS},
        })
        print(f"  redone {r['model']:28s} {r['sid']}/{r['style']}/t{r['trial']} "
              f"finish={res['finish_reason']} len={len(res['text'] or '')}")

    print(f"\nACTUAL SPEND (token-priced): ${driver.spend_so_far():.4f}")
    print("finish reasons:", driver.FINISH)


if __name__ == "__main__":
    main()
