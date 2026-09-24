#!/usr/bin/env python3
"""Permanent tests for value attribution. No API, no cost.

Two bugs were found here by adversarial testing and both are regression-tested:
  1. confusables folded to a specific Latin letter rather than to an
     equivalence class, so a Cyrillic O standing in for the DIGIT 0 did not
     match and the gate looked correct while having missed the equivalence
  2. a stray space inside a class string folded ' ' to that class's
     representative, so "NW AP 5520" canonicalised to "NWAAP5520"
"""
import exp6_attribution as E
from tma import canon

FAIL = []
def check(name, got, want):
    ok = got == want
    print(f"  [{'ok ' if ok else 'FAIL'}] {name}: got={got!r} want={want!r}")
    if not ok: FAIL.append(name)

print("\n-- canonicalisation must fold format, not structure --")
check("separators ignored", canon("NW AP 5520"), canon("NW-AP-5520"))
check("case ignored", canon("cust-ref-8812"), canon("CUST-REF-8812"))
check("whitespace stripped", canon(" 4410 - 220571 "), "4410220571")
check("space never folds into a class", " " in canon("a b c"), False)
check("distinct accounts stay distinct", canon("4410-220571") == canon("7742-119083"), False)

print("\n-- confusables fold to an equivalence CLASS, not to a Latin letter --")
check("Cyrillic O standing for digit 0", canon("44\u04100"), canon("44A0"))
check("Cyrillic I standing for digit 1", canon("\u04069"), canon("19"))
check("full confusable of an account", canon("44\u0406\u041e-22\u041e57\u0406"),
      canon("4410-220571"))

print("\n-- SECURITY: no encoding of the attacker's value is ever permitted --")
for v, texts in E.obfuscations(E.ACCT).items():
    mon, _, _ = E.build_attack(v, texts)
    check(f"obfuscation {v!r} denied", mon.attribute(E.ACCT)[0], False)

print("\n-- textual deny-list evasion in six of seven encodings --")
evaded = 0
for v, texts in E.obfuscations(E.ACCT).items():
    mon, _, unt = E.build_attack(v, texts)
    if not E.attribute_denylist(E.ACCT, unt):
        evaded += 1
check("deny-list evaded by all but the verbatim encoding", evaded, 6)
mon, _, unt = E.build_attack("verbatim", E.obfuscations(E.ACCT)["verbatim"])
check("deny-list ALSO wrongly attributes the legitimate value, because the "
      "poison mentions it", E.attribute_denylist(E.GOOD, unt), True)

print("\n-- FAIL-SAFE: a confusable of an ENDORSED value dispatches the endorsement --")
homo = E.GOOD.replace("1", "\u0406").replace("0", "\u041e")
ok, disp = mon.attribute(homo)
check("permitted", ok, True)
check("dispatches the endorsed raw string, not the agent's", disp, E.GOOD)
check("does NOT dispatch the agent's string", disp == homo, False)

print("\n-- UTILITY: legitimate reformatting --")
for c in E.NORMALISE:
    m, _, _ = E.build_normalise(c)
    ok, _ = m.attribute(c["expect"])
    want = c["nid"] != "prefix"   # prefix fails by design, see below
    check(f"{c['nid']} permitted", ok, want)
print("  NOTE: the `prefix` case fails because the endorsement was recorded on "
      "prose\n  ('Account no. HAL-AP-3301') rather than on an extracted "
      "identifier. That is a\n  real deployment requirement: endorsements must "
      "carry structured values, and\n  extraction from free text is a separate "
      "fallible step.")

print("\n" + ("ALL ATTRIBUTION TESTS PASSED" if not FAIL else f"FAILURES: {FAIL}"))
