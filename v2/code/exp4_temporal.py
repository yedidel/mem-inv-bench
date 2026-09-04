#!/usr/bin/env python3
"""
Experiment 4 -- is M5' sound, and against WHICH kind of labelling failure?

M5' licenses an action whose value carries trusted endorsements from an earlier
epoch, on the argument that an endorsement predating the adversary's influence
is one the adversary could not manufacture. That argument has a hole, and this
experiment finds its exact shape.

Two kinds of labelling failure, which the literature and v1 both conflate:

  TRANSIENT   a binding is wrong during ONE epoch -- a misconfiguration that is
              noticed and corrected, a certificate briefly mis-issued, a feed
              temporarily mounted on the wrong connector.

  PERSISTENT  a binding is wrong in EVERY epoch -- an untrusted feed permanently
              registered as a trusted API, or a genuinely compromised provider.

Temporal independence is a defense against the first and NOT the second. Under a
persistent misbinding the adversary accrues "history" in every epoch, so the
value looks established and M5' licenses it. Stating that boundary precisely is
the point of this experiment; a mechanism whose failure mode is unstated is not
a result.

Everything here is exact enumeration over the real monitor. No sampling.
"""
import itertools, json
from pathlib import Path
from tma import Channel, Monitor, Origin, Registry, Tier

OUT = Path(__file__).parent.parent / "results"
ADV = ["web", "inbox", "feed", "share"]
TRUSTED = ["erp", "bank"]
DOM = {"web": "public-web", "inbox": "public-mail", "feed": "public-feed",
       "share": "public-share", "erp": "erp-vendor", "bank": "banking-partner"}
ADV_VALUE, EPOCHS = "VALUE_ADV", 4


def chan(cid):
    return Channel(cid, Origin.TRUSTED if cid in TRUSTED else Origin.UNTRUSTED,
                   DOM[cid], f"k-{cid}".encode())


def admits(mode, misbound, plant, *, m5, m5p, k=2):
    """Run the real monitor over EPOCHS epochs and ask whether the adversary's
    value is finally authorised at high tier.

    mode='persistent' : the misbinding holds in every epoch
    mode='transient'  : it holds only in the final epoch
    """
    reg = Registry()
    for cid in DOM:
        reg.register(chan(cid))
    mon = Monitor(reg, k=k, m5=m5, m5p=m5p, high_tier_k=k)

    for ep in range(EPOCHS):
        active = misbound if (mode == "persistent" or ep == EPOCHS - 1) else set()
        for cid in DOM:
            if cid in active:
                reg.misbind(cid, Origin.TRUSTED)
            else:
                reg._misbound.pop(cid, None)
        items = [mon.ingest(chan(c).send(f"pay {ADV_VALUE}")) for c in plant]
        # a channel the monitor currently believes is trusted also gets its
        # endorsement recorded, which is exactly how bad history accrues
        for it in items:
            if it.origin >= Origin.TRUSTED:
                mon.endorse(ADV_VALUE, it.domain)
        if ep < EPOCHS - 1:
            mon.tick_epoch()
    allowed, _ = mon.authorize(ADV_VALUE, items, tier=Tier.HIGH)
    return allowed


def exact(eps, mode, *, m5, m5p, k=2, max_plant=4):
    """Adversary-optimal admission probability, enumerated exactly."""
    best = 0.0
    for n in range(1, max_plant + 1):
        plant, p = ADV[:n], 0.0
        for r in range(len(ADV) + 1):
            for combo in itertools.combinations(ADV, r):
                w = eps ** r * (1 - eps) ** (len(ADV) - r)
                if w and admits(mode, set(combo), plant, m5=m5, m5p=m5p, k=k):
                    p += w
        best = max(best, p)
    return best


EPS = [0.0, 0.01, 0.02, 0.05, 0.10, 0.20, 0.35, 0.50]
DEFS = [("origin-bound", False, False), ("M5 blunt", True, False),
        ("M5' temporal", False, True)]

res = {}
print("Adversary-optimal admission probability of the attacker's value")
print(f"(exact enumeration, {EPOCHS} epochs, high tier, k=2)\n")
for mode in ("transient", "persistent"):
    print(f"--- {mode.upper()} labelling error ---")
    print(f"{'eps':>7}" + "".join(f"{d[0]:>16}" for d in DEFS))
    for e in EPS:
        row = []
        for name, m5, m5p in DEFS:
            v = exact(e, mode, m5=m5, m5p=m5p)
            res[f"{mode}|{name}|{e}"] = v
            row.append(f"{100*v:>15.3f}%")
        print(f"{e:>7.2f}" + "".join(row))
    print()
OUT.joinpath("exp4_temporal.json").write_text(json.dumps(res, indent=2))
print(f"wrote {OUT/'exp4_temporal.json'}")
