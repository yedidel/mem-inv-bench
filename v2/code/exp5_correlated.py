#!/usr/bin/env python3
"""
Experiment 5 -- correlated labelling errors, the weakness exp2 leaves open.

exp2 treats each channel binding as independently wrong with probability eps.
Real misbindings are not independent: one bad deployment script mounts several
feeds behind the same connector, one mis-issued certificate covers a whole
provider, one operator mistake repeats across a batch. If errors are correlated,
M5's requirement of k INDEPENDENT trust domains buys much less than exp2 says,
because a single fault supplies all k at once.

This is the most dangerous unexamined assumption remaining in the quantitative
story, so it gets measured rather than assumed away.

MODEL. Total marginal error rate eps is split between two mechanisms by a
correlation share lambda:

  common cause  with probability lambda*eps a SINGLE latent fault misbinds every
                adversary-reachable channel at once
  independent   otherwise each channel is independently wrong at a rate chosen
                so the marginal per-channel error stays exactly eps

lambda = 0 reproduces exp2. lambda = 1 is a purely systemic failure mode.
Everything is enumerated exactly over the real monitor; nothing is sampled.
"""
import itertools, json
from pathlib import Path
from tma import Channel, Monitor, Origin, Registry, Tier

OUT = Path(__file__).parent.parent / "results"
ADV = ["web", "inbox", "feed", "share"]
TRUSTED = ["erp", "bank"]
DOM = {"web": "public-web", "inbox": "public-mail", "feed": "public-feed",
       "share": "public-share", "erp": "erp-vendor", "bank": "banking-partner"}
VAL = "VALUE_ADV"


def chan(c):
    return Channel(c, Origin.TRUSTED if c in TRUSTED else Origin.UNTRUSTED,
                   DOM[c], f"k-{c}".encode())


def admits(misbound, plant, *, m5, k=2):
    reg = Registry()
    for c in DOM:
        reg.register(chan(c))
    for c in misbound:
        reg.misbind(c, Origin.TRUSTED)
    mon = Monitor(reg, k=k, m5=m5, high_tier_k=k)
    sup = [mon.ingest(chan(c).send(f"pay {VAL}")) for c in plant]
    return mon.authorize(VAL, sup, tier=Tier.HIGH)[0]


def exact(eps, lam, *, m5, k=2):
    """Adversary-optimal admission probability under the mixture model."""
    p_common = lam * eps
    # independent rate chosen so the marginal per-channel error is exactly eps
    p_ind = 0.0 if p_common >= eps else (eps - p_common) / (1 - p_common)
    best = 0.0
    for n in range(1, len(ADV) + 1):
        plant = ADV[:n]
        # branch 1: the common fault fires -> every channel misbound
        p = p_common * (1.0 if admits(set(ADV), plant, m5=m5, k=k) else 0.0)
        # branch 2: no common fault -> independent misbindings
        for r in range(len(ADV) + 1):
            for combo in itertools.combinations(ADV, r):
                w = (1 - p_common) * p_ind ** r * (1 - p_ind) ** (len(ADV) - r)
                if w and admits(set(combo), plant, m5=m5, k=k):
                    p += w
        best = max(best, p)
    return best


EPS = [0.01, 0.02, 0.05, 0.10, 0.20]
LAMS = [0.0, 0.25, 0.50, 0.75, 1.0]

res = {}
print("Adversary-optimal admission probability, high tier, k=2")
print("exact enumeration; lambda = share of the error that is common-cause\n")
print(f"{'eps':>6}{'lambda':>8}{'origin-bound':>15}{'M5':>12}{'M5 advantage':>15}")
for e in EPS:
    for lam in LAMS:
        ob = exact(e, lam, m5=False)
        m5 = exact(e, lam, m5=True)
        res[f"{e}|{lam}"] = {"originbound": ob, "m5": m5}
        adv = (ob / m5) if m5 > 0 else float("inf")
        advs = f"{adv:13.1f}x" if adv != float("inf") else "          inf"
        print(f"{e:>6.2f}{lam:>8.2f}{100*ob:>14.3f}%{100*m5:>11.3f}%{advs}")
    print()
OUT.joinpath("exp5_correlated.json").write_text(json.dumps(res, indent=2))
print(f"wrote {OUT/'exp5_correlated.json'}")
