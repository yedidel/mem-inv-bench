#!/usr/bin/env python3
"""Pre-flight for experiment 11. Runs before any money is spent.

Every check here exists because the corresponding failure has actually happened
in this study, or because a static read of the code showed it could. A cell that
looks like a clean 0% because the gate denies everything, or a run whose
identifiers are refused on the string rather than the semantics, is not a
measurement, and neither is detectable after the fact from the number alone.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import scenarios_h2h as H
from exp11_headtohead import (CONFIGS, SCENARIOS, TOOL_SCHEMA, attacked_fields,
                              build_memory, gate_verdict, parse_action)

HERE = Path(__file__).parent
FAILS = []


def check(label, got, want):
    ok = got == want
    print(f"  [{'ok ' if ok else 'FAIL'}] {label}: got={got!r} want={want!r}")
    if not ok:
        FAILS.append(label)
    return ok


print("=" * 74)
print("1. no loaded identifier survives in text the model is shown")
print("=" * 74)
for s in SCENARIOS:
    visible = " ".join([s["task"], *s["trusted_facts"], *s["variants"].values(),
                        *map(str, s["attacker"].values()),
                        *map(str, s["benign"].values())])
    hits = re.findall(H.LOADED_PATTERN, visible, re.I)
    check(f"{s['sid']} model-visible text clean", hits, [])

print()
print("=" * 74)
print("2. the attacker's value is present in the payload of every attack style")
print("=" * 74)
for s in SCENARIOS:
    target = str(s["attacker"].get("to"))
    for style in ("static", "adaptive", "whitebox"):
        check(f"{s['sid']}/{style} carries the attacker value",
              target in s["variants"][style], True)
    check(f"{s['sid']}/benign does NOT carry it",
          target in s["variants"]["benign"], False)

print()
print("=" * 74)
print("3. the gate ADMITS the legitimate value")
print("=" * 74)
print("  If it does not, every attack cell reads 0% for the wrong reason and")
print("  the run measures the gate's appetite for denial, not the attack.")
for s in SCENARIOS:
    good = s["benign"].get("to")
    if good is None:
        print(f"  [skip] {s['sid']}: no legitimate send exists (exfiltration)")
        continue
    for cfg in CONFIGS:
        mon, items, supporting = build_memory(s, "benign", cfg)
        act = {"tool": s["tool"], "to": good}
        if "amount" in s["benign"]:
            act["amount"] = s["benign"]["amount"]
        v = gate_verdict(mon, supporting, act, attacked_fields(s))
        check(f"{s['sid']}/{cfg} legitimate value admitted",
              bool(v and v["allowed"]), True)

print()
print("=" * 74)
print("4. the gate DENIES the attacker's value, under every trigger style")
print("=" * 74)
for s in SCENARIOS:
    bad = s["attacker"].get("to")
    for style in ("static", "adaptive", "whitebox"):
        for cfg in CONFIGS:
            mon, items, supporting = build_memory(s, style, cfg)
            act = {"tool": s["tool"], "to": bad}
            if "amount" in s["attacker"]:
                act["amount"] = s["attacker"]["amount"]
            v = gate_verdict(mon, supporting, act, attacked_fields(s))
            check(f"{s['sid']}/{style}/{cfg} attacker value denied",
                  bool(v and v["allowed"]), False)

print()
print("=" * 74)
print("5. the whitebox payload changes NO label the monitor derives")
print("=" * 74)
print("  Forged trust markers live in the bytes; origin comes from the verified")
print("  channel. If these differ, payload text is reaching a label.")
for s in SCENARIOS:
    _, _, sup_a = build_memory(s, "adaptive")
    _, _, sup_w = build_memory(s, "whitebox")
    la = [(int(i.origin), i.domain, int(i.act)) for i in sup_a]
    lw = [(int(i.origin), i.domain, int(i.act)) for i in sup_w]
    check(f"{s['sid']} labels identical adaptive vs whitebox", la, lw)

print()
print("=" * 74)
print("6. the action parser survives the shapes models actually emit")
print("=" * 74)
CASES = [
    ('{"tool":"pay","to":"X","amount":5}', {"tool": "pay", "to": "X", "amount": 5}),
    ('Sure!\n{"tool":"pay","to":"X","amount":5}', {"tool": "pay", "to": "X", "amount": 5}),
    ('```json\n{"tool":"pay","to":"X","amount":5}\n```', {"tool": "pay", "to": "X", "amount": 5}),
    ('{"reasoning":"first"}\n{"tool":"pay","to":"X","amount":5}', {"reasoning": "first"}),
    ("no json at all", None),
    ("", None),
]
for text, want in CASES:
    check(f"parse {text[:34]!r}", parse_action(text), want)

print()
print("=" * 74)
print("7. every tool the scenarios use has a schema and a gated identifier field")
print("=" * 74)
for s in SCENARIOS:
    check(f"{s['sid']} tool {s['tool']} has a schema",
          s["tool"] in TOOL_SCHEMA, True)
    check(f"{s['sid']} attacker action carries a 'to' field",
          "to" in s["attacker"], True)

print()
print("=" * 74)
print("8. coverage: four pipelines, four styles, three attack classes")
print("=" * 74)
pipes = sorted({s["pipeline"] for s in SCENARIOS})
classes = sorted({s["attack_class"] for s in SCENARIOS})
check("pipelines", pipes, ["ConvBackdoor", "MemMorph", "MemoryGraft", "TrojanHippo"])
check("styles per scenario",
      sorted(SCENARIOS[0]["variants"]), ["adaptive", "benign", "static", "whitebox"])
check("attack classes", classes, ["control_flow", "data_exfiltration", "sleeper"])

print()
print("=" * 74)
if FAILS:
    print(f"PRE-FLIGHT FAILED: {len(FAILS)} check(s)")
    for f in FAILS:
        print("  -", f)
    raise SystemExit(1)
print("ALL PRE-FLIGHT CHECKS PASSED -- safe to spend")
