#!/usr/bin/env python3
"""
Statistics for MEM-INV-Bench (numpy only; no scipy dependency).

Reads results.json (which carries raw hits/n per cell) and produces:
  - Wilson 95% confidence intervals for each consequential-ASR / utility proportion,
  - a pooled two-proportion comparison of temporal_auth vs each baseline, with a
    permutation p-value (exact-ish via Monte Carlo) for the consequential-ASR gap.

No randomness from Date/time; the permutation seed is fixed for reproducibility.
"""
import json
import math
from pathlib import Path

import numpy as np

HERE = Path(__file__).parent


def wilson(hits, n, z=1.96):
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = hits / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return (100 * p, 100 * max(0.0, center - half), 100 * min(1.0, center + half))


EXCLUDE = set()   # all reported models are reliable (0% empty under the guard)


def pooled(results, defense, buckets):
    """Pool hits/n across models (excluding unreliable ones) for the given buckets."""
    h = n = 0
    for m in results:
        if m in EXCLUDE:
            continue
        raw = results[m][defense]["raw"]
        for b in buckets:
            h += raw[f"{b}_hit"]
            n += raw[f"{b}_n"]
    return h, n


def perm_test(h1, n1, h2, n2, iters=20000, seed=12345):
    """Two-sided permutation test on the difference in proportions (pooled labels)."""
    rng = np.random.default_rng(seed)
    obs = abs(h1 / n1 - h2 / n2) if n1 and n2 else 0.0
    labels = np.array([1] * h1 + [0] * (n1 - h1) + [1] * h2 + [0] * (n2 - h2))
    count = 0
    for _ in range(iters):
        rng.shuffle(labels)
        a, b = labels[:n1], labels[n1:]
        diff = abs(a.mean() - b.mean())
        if diff >= obs - 1e-12:
            count += 1
    return obs, (count + 1) / (iters + 1)


def main():
    data = json.loads((HERE / "results.json").read_text(encoding="utf-8"))
    results = data["results"]
    defenses = list(next(iter(results.values())).keys())
    cons = ["cons_static", "cons_adapt", "cons_white"]

    print(f"models: {len(results)}   defenses: {defenses}")
    print("\n=== Pooled consequential-ASR by trigger type, Wilson 95% CI ===")
    for trig, b in [("static", "cons_static"), ("adaptive", "cons_adapt"),
                    ("whitebox", "cons_white")]:
        print(f"  -- {trig} --")
        for d in defenses:
            h, n = pooled(results, d, [b])
            if n == 0:
                continue
            p, lo, hi = wilson(h, n)
            print(f"     {d:<14} {p:5.1f}%  [{lo:4.1f}, {hi:4.1f}]   ({h}/{n})")

    print("\n=== Pooled consequential-ASR (all triggers) with Wilson 95% CI ===")
    pooled_stats = {}
    for d in defenses:
        h, n = pooled(results, d, cons)
        p, lo, hi = wilson(h, n)
        pooled_stats[d] = (h, n)
        print(f"  {d:<14} {p:5.1f}%  [{lo:4.1f}, {hi:4.1f}]   ({h}/{n})")

    print("\n=== Utility (all models) with Wilson 95% CI ===")
    for d in defenses:
        h, n = pooled(results, d, ["util"])
        p, lo, hi = wilson(h, n)
        print(f"  {d:<14} {p:5.1f}%  [{lo:4.1f}, {hi:4.1f}]   ({h}/{n})")

    print("\n=== temporal_auth vs baselines: consequential-ASR gap (permutation test) ===")
    ht, nt = pooled_stats["temporal_auth"]
    for d in defenses:
        if d == "temporal_auth":
            continue
        hb, nb = pooled_stats[d]
        diff, p = perm_test(hb, nb, ht, nt)
        star = "***" if p < 0.001 else "**" if p < 0.01 else "*" if p < 0.05 else "ns"
        print(f"  vs {d:<12} dASR={100*diff:5.1f} pts   p={p:.4g}  {star}")


if __name__ == "__main__":
    main()
