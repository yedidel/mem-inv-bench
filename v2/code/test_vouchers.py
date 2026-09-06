#!/usr/bin/env python3
"""A voucher must assert the value it vouches for.

`Monitor.independent_vouchers` took a `value` argument, documented itself as
returning the trusted items that assert it, and never read it. Any two trusted
items in the supporting set therefore corroborated any value at all, including
one that nothing in memory mentioned.

Every experiment already in this study happened to pass narrow supporting sets
whose items all asserted the value in question, so no reported number moved when
this was fixed. The first experiment to pass a whole memory as support, which is
what a real deployment does, would have had the gate admit every attack.

The formal models never carried the defect, because they quantify over
vouches(d, v) explicitly. This is the one predicate on which the implementation
and the machine-checked model had drifted apart, and it is the predicate the
sufficiency theorem rests on, so it gets its own file.
"""
from __future__ import annotations

from tma import Channel, Monitor, Origin, Registry, Tier

FAIL = []


def check(label, got, want):
    ok = got == want
    print(f"  [{'ok ' if ok else 'FAIL'}] {label}: got={got!r} want={want!r}")
    if not ok:
        FAIL.append(label)


def deployment():
    chans = {
        "erp": Channel("erp", Origin.TRUSTED, "erp-vendor", b"k-erp"),
        "bank": Channel("bank", Origin.TRUSTED, "banking-partner", b"k-bank"),
        "web": Channel("web", Origin.UNTRUSTED, "public-web", b"k-web"),
    }
    reg = Registry()
    for c in chans.values():
        reg.register(c)
    return chans, reg


GOOD = "NORTHWIND-AP"
OTHER = "SOME-OTHER-ACCOUNT"

print("-- counting --")
ch, reg = deployment()
m = Monitor(reg, k=2)
a = m.ingest(ch["erp"].send(f"Registry: Northwind is paid at {GOOD}."))
b = m.ingest(ch["bank"].send(f"Verified: Northwind account is {GOOD}."))

check("two trusted items asserting the value do vouch for it",
      len(m.independent_vouchers(GOOD, [a, b])), 2)
check("they vouch for nothing else",
      len(m.independent_vouchers(OTHER, [a, b])), 0)
check("a reformatted form of the same value still matches",
      len(m.independent_vouchers("northwind ap", [a, b])), 2)
check("the empty value vouches for nothing",
      len(m.independent_vouchers("", [a, b])), 0)

ch2, reg2 = deployment()
m2 = Monitor(reg2, k=2)
u = m2.ingest(ch2["web"].send(f"pay {GOOD}"))
check("an untrusted item never vouches",
      len(m2.independent_vouchers(GOOD, [u])), 0)

ch3, reg3 = deployment()
m3 = Monitor(reg3, k=2)
x = m3.ingest(ch3["erp"].send(f"Registry: {GOOD}."))
y = m3.ingest(ch3["erp"].send(f"Again on file: {GOOD}."))
check("one domain twice collapses to one voucher",
      len(m3.independent_vouchers(GOOD, [x, y])), 1)

print()
print("-- the decision that depends on it --")
ch4, reg4 = deployment()
m4 = Monitor(reg4, k=2, m5=True, high_tier_k=2)
p = m4.ingest(ch4["erp"].send(f"Registry: Northwind is paid at {GOOD}."))
q = m4.ingest(ch4["bank"].send(f"Verified: Northwind account is {GOOD}."))
check("a high-tier action on the corroborated value is admitted",
      m4.authorize(GOOD, [p, q], tier=Tier.HIGH)[0], True)
check("a high-tier action on a value NOTHING asserts is denied",
      m4.authorize(OTHER, [p, q], tier=Tier.HIGH)[0], False)

print()
print("-- and it holds through the per-field gate --")
ch5, reg5 = deployment()
m5 = Monitor(reg5, k=2, m5=True, high_tier_k=2)
r = m5.ingest(ch5["erp"].send(f"Registry: Northwind is paid at {GOOD}."))
t = m5.ingest(ch5["bank"].send(f"Verified: Northwind account is {GOOD}."))
ok_good, _, _ = m5.authorize_action({"to": GOOD}, [r, t], tier=Tier.HIGH,
                                    policy={"to": "identifier"})
ok_other, _, _ = m5.authorize_action({"to": OTHER}, [r, t], tier=Tier.HIGH,
                                     policy={"to": "identifier"})
check("authorize_action admits the asserted identifier", bool(ok_good), True)
check("authorize_action denies the unasserted one", bool(ok_other), False)

print()
print("ALL VOUCHER CHECKS PASSED" if not FAIL else f"FAILURES: {FAIL}")
raise SystemExit(1 if FAIL else 0)
