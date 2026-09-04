# Does each experiment answer the need it was run for?

An honest pass, including where the answer is no.

## exp1 -- attack propensity, de-circularised

**Need.** Three reviewers said the primary evaluation handed the gate its own
answer key (`authorized("tma_nm")` read `true_origin`, written by the scenario
builder in the same file). exp1 measures the one quantity that genuinely
requires an LLM: whether the agent commits the attacker's value.

**Answers it?** Yes. Labels are derived only from a verified channel identity;
no ground-truth field exists downstream.

**Strengthens the paper?** Yes, two ways.
- Pooled propensity 79.5% [76.8, 81.8] over 985 decided cells shows undefended
  susceptibility has NOT been solved by model progress, which the paper needs or
  the whole problem evaporates.
- The content class is measured, not stipulated: the same poison framed as a
  tool lookup collapses write-time detection from 87% to 17%. v1 asserted
  `looks_benign` per channel; this is the observed version, and it is a
  stronger witness for T1 than anything in v1.

**Weakness, stated.** exp1 measures propensity, not end-to-end ASR per defense.
The defense comparison is propensity x exact gate enumeration. That
decomposition is defensible and more precise than sampling, but it is a design
choice the paper must argue for explicitly rather than slip past a reader.

**Second weakness.** Single-shot memory, not a multi-turn agent loop. exp3
covers the longitudinal case; a genuine tool-using loop is still missing.

## exp2 -- exact degradation under imperfect labelling

**Need.** R2: "An experiment is necessary where channel labeling is imperfect,
and report how the guarantee degrades." R1 and R3 raised it three more times.

**Answers it?** Yes, and exactly: ASR = eps for origin-binding, which is the
empirical face of the new theorem T2.

**Strengthens the paper?** Yes. It is the centerpiece and it converts v1's
largest unexamined assumption into a measured curve.

**Weakness, stated.** The error model is i.i.d. per channel binding. Real
misbindings correlate -- one bad deployment script mounts several feeds on the
same connector. A correlated-error sweep is not yet run, and until it is, the
eps^2 claim for M5 is optimistic: correlated errors move it back toward eps.
This is a known gap, not a resolved one.

## exp3 -- does accumulated legitimate history protect the agent? [RUNNING]

**Need.** M5' rests on a claim about the world: an attack must introduce a value
that is not the established one. That leaves unmeasured whether the model itself
already resists a "the account changed" note once it has paid the established
account many times.

**Will it answer?** Yes, and informatively either way. If history protects, the
system mechanism buys less than claimed and the paper must say so. If it does
not, the mechanism is doing work the model cannot do for itself.

**Distinct from v1?** Yes, and this matters. v1's persistence sweep varied the
number of IDLE intervening sessions, which tests dormancy. Here the intervening
sessions contain real successful payments recorded in the monitor's log, which
tests history. v1's persistence figure must NOT be carried over.

## exp4 -- when is temporal independence sound?

**Need.** M5' claims an endorsement from an earlier epoch is independent of the
adversary. That claim needed attacking before it could be used.

**Answers it?** Yes, sharply. M5' keeps all of M5's security against a TRANSIENT
labelling error at near-zero utility cost, and collapses exactly to
origin-binding against a PERSISTENT one.

**Strengthens the paper?** Yes, and this is the kind of result v1 had none of: a
mechanism with a precisely characterised failure mode. It also produces the
paper's ceiling -- beyond eps ~ 0.35 every option converges, because the
adversary just seeds more channels. A defense whose limits are stated is more
credible than one reporting 0% everywhere.

## Formal model (MemAuth2.tla)

**Need.** v1's T3 held by propositional logic: the security predicate was the
gate's own guard. R3 identified it.

**Answers it?** Yes. The predicate is now semantic, over the adversary's goal
and genuine endorsement facts no gate reads; the adversary is quantified over a
mutation class rather than three named moves; and store eviction and
consolidation break the coincidence where the gate would recompute the property.

**Remaining gap, unresolved.** R1's FIRST listed flaw was "a hand-waved
parameter-independence claim, not a mechanized proof". The tautology is fixed but
the unboundedness is not: results are for Slots={s1,s2,s3}, Values=2, Domains=2,
K=2. TLAPS is not installed on this machine. Until the unbounded proof exists,
R1's lead objection is only half answered, and the paper must not claim
otherwise.

## What must NOT be carried over from v1

| v1 result | why it must be dropped |
|---|---|
| unified benchmark, "TMA-NM 0% ASR at 100% utility" | the gate read `true_origin`; circular |
| cross-model study, "0/4032" | same gate, plus loaded attacker identifiers |
| ablation table | built on the circular gate |
| persistence sweep | idle sessions, not history; superseded by exp3 |
| content baseline failure rates (47-68%) | `looks_benign` was stipulated per channel, and the identifiers were loaded; exp1 measures this properly |
| head-to-head vs four published attacks | worth redoing on the v2 harness, but the v1 numbers carry the same circularity |
| Mem0 backend result | the guarantee it demonstrated is the circular one |
| threshold and independence sub-studies | superseded by exp2 and exp4, which compute the same thing exactly |
| "100% legit-utility, zero usability cost" | the scenarios always supplied two vouchers; this is the claim R2 said cannot stand |

Isolation is enforced mechanically: no v2 module imports or reads anything under
the v1 tree, and `logs/STUDY_MANIFEST.txt` lists exactly which transcripts may
enter a reported number.

## Experiments still missing, in priority order

1. **Value attribution under an obfuscating adversary.** R1.3, R1.10, R3.12 and
   v1's own limitation (c). The whole guarantee assumes the monitor knows which
   retrieved value drove the action. v1 used text matching and admitted it was
   evadable. Not yet addressed in v2 either, and it is the largest hole.
2. **Label-drift detection.** R1.2 asked for an operational response to channel
   compromise. exp4 now makes it necessary rather than optional: it is the only
   thing that turns M5's persistent-error blind spot into a detectable event.
3. **Correlated label errors** (the exp2 weakness above).
4. **Baselines against original artifacts**, marked as reimplementations where
   no artifact exists. R2 asked for this explicitly.
5. **Multi-turn tool-using loop**, so the guarantee is shown over real
   cross-turn dataflow rather than a single proposal.
