# Formal verification of the TMA monitor

Two complementary machine-checked artifacts establish the action-integrity invariant.

## 1. TLA+ model check (TLC) — the headline result
`MemoryInvariants.tla` models the write→retrieve→act pipeline over bounded memory
slots; `Security` is the invariant "an untrusted, un-elevated item never causes a
consequential action unless it rode a fresh user authorization."

Run (requires Java + `tla2tools.jar`, downloaded into this dir):
```bash
# PROOF: write-time binding ON -> invariant holds over all reachable states
java -cp tla2tools.jar tlc2.TLC -config MemoryInvariants.cfg MemoryInvariants.tla
# NECESSITY: binding OFF -> TLC returns a counterexample
java -cp tla2tools.jar tlc2.TLC -config MemoryInvariants_necessity.cfg MemoryInvariants.tla
```

Verified results (TLC 2.19, Slots={s1,s2,s3}, MaxSession=3):
- **Binding=TRUE:** `Model checking completed. No error has been found.`
  2144 distinct reachable states; `Security` holds in all of them.
- **Binding=FALSE:** `Invariant Security is violated.` 3-state counterexample
  (Init → Write untrusted → Act) — write-time binding (M1) is load-bearing.

## 1b. SEPARATION THEOREM (TLC) — the keystone of Non-Malleable Memory Authority
`MemAuthority.tla` model-checks a defense-class separation under a laundering adversary
(moves: Paraphrase = drop derivation edge + benign-ify content; plus honest Write,
Elevate, GrantUserAuth, Tick). The `Security` invariant is defense-INDEPENDENT (speaks
only of true origin, genuine elevation, user-auth), so it measures real soundness.
CONSTANT `Defense` selects the act-gate's authority rule. Verified (TLC 2.19,
Slots={s1,s2,s3}, MaxSession=2, Launder=TRUE):
- **Defense="content"** -> `Invariant Security is violated` (witness: Write untrusted ->
  Paraphrase -> Act). **T1 insufficiency** of content/trust-scoring defenses.
- **Defense="lineage"** -> `Invariant Security is violated` (same laundering witness via
  the no-strong-edge fallback). **T1 insufficiency** of malleable-lineage (MemLineage-style).
- **Defense="nonmalleable"** -> `Model checking completed. No error` over 3270 reachable
  states. **T3 sufficiency** of origin-bound authority + corroboration-gated elevation.
Run:
```bash
for D in content lineage nonmalleable; do
  java -cp tla2tools.jar tlc2.TLC -config MA_$D.cfg MemAuthority.tla; done
```
Together with MemoryInvariants.tla's necessity result (binding off -> reachable
violation), this machine-checks the insufficiency (T1), necessity (T2/N), and
sufficiency (T3) directions of the separation.

## 1c. UNBOUNDED guarantee via an inductive invariant (MA_ind.cfg)
Bounded TLC checks one model size. To lift the sufficiency (T3) result to UNBOUNDED
executions we give an inductive invariant and verify the inductive STEP with TLC:
`MA_ind.cfg` sets `INIT IndInv` (start from ALL states satisfying IndInv, including
non-reachable ones) and checks `Next` preserves it. Result: **"No error has been
found."** -> IndInv is inductive. Since the per-action case analysis (see the comment in
MemAuthority.tla) is independent of |Slots| and MaxSession, the same invariant holds for
any number of memory items and sessions -> an unbounded safety guarantee, not just a
finite-model check. (IndInv = TypeOK + bookkeeping consistency + Security; finding it
required the standard strengthening to exclude spurious non-reachable states, e.g. "one
cannot act on an empty slot".) A fully mechanized deductive proof (TLAPS/Lean) is a
further step; the inductive-invariant check already yields the unbounded result.

## 2. Exhaustive check against the implementation
`../check_invariant.py` exhaustively checks the *actual Python monitor* (not a separate
abstraction): P (Action Integrity, 120 configs), E (Elevation Soundness, 64 sets),
R (end-to-end safety), N (necessity counterexample with binding off). Run:
```bash
python ../check_invariant.py
```

Together: TLC proves the abstract state machine; the Python checker ties the same
invariant to the running code. Future work: a fully mechanized unbounded proof via an
inductive invariant in TLAPS (Java toolchain already present).
