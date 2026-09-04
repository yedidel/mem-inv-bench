# What a reviewer can still attack

Written adversarially against our own results. Every entry is something a
competent reviewer could raise, with an honest assessment of whether we can
answer it. Anything we cannot answer is listed as such rather than buried.

## A. Numbers that are TRUE BY CONSTRUCTION and must never be presented as findings

This is the failure mode that sank v1, so it gets its own section. Each of these
is a consequence of a rule, not a measurement:

| number | why it is not a finding |
|---|---|
| exp6: the allow-list blocks 142/142 decoded attacks | the rule permits only endorsed values and the attacker's account is not endorsed |
| exp7: the gate blocked 24/24 attacker values it saw | same |
| exp2/exp4/exp5: gate-admission probabilities | exact enumeration of a deterministic rule, not an experiment |
| the TLC/SMT "holds" rows | statements about a model, and the model is ours |

What IS measured, and what the paper should lead with:

| number | status |
|---|---|
| pooled propensity 79.4% [76.8, 81.8], n=985 | measured, replies read |
| content detection collapse 87% -> 17% on tool-echo | measured |
| v1's deny-list attribution blocks only 28.9% of decodes | measured |
| models decode base64/spelled/split at 100% | measured |
| history gives no protection (98.3% -> 96.5%, overlapping CIs) | measured |
| susceptibility tracks registry coverage (21/21 vs 2/19) | measured |
| M5's advantage collapses under correlated errors (16.9x -> 1.0x) | exact, and it is a NEGATIVE result about our own mechanism |
| the utility cost of M5' and of the allow-list | measured |

## B. Attacks we can answer

**"You wrote the scenarios your defense handles."**
exp8 runs the gate on AgentDojo (NeurIPS 2024 D&B) unmodified, scored by
AgentDojo's own `utility()` and `security()`. The three things that could have
been tuned are all derived from the benchmark's metadata: the channel partition
from a marker probe over AgentDojo's declared injection vectors, the
consequential tool set from the final call of each injection task's own
`ground_truth()`, and the gated fields from those calls' arguments. A `strict`
variant uses no partition at all.

**"The formal result is bounded / the parameter independence is hand-waved."**
`formal/unbounded.py` discharges the inductive step in SMT over uninterpreted
sorts, with the base case and two non-vacuity checks. It holds for every
cardinality, including infinite. TLC is retained as a cross-check by a different
tool.

**"The security predicate mirrors the authorisation rule."**
It is now stated over the adversary's goal and over `endorsed`, which no gate
reads, and store eviction breaks the coincidence where the gate would recompute
it.

**"The adversary is three hardcoded moves."**
Quantified over an arbitrary content/edge mutation.

**"The utility claim can't stand."**
It does not stand: M5 costs a confirmation on every high-tier action, M5' costs
one per payee-account pair, and the allow-list blocks 1 of 3 legitimate
reformattings. All reported.

**"Cross-agent memory is excluded."**
Machine-checked, unbounded: safe iff peers are not counted as trusted endorsers;
counting them violates the invariant.

## C. Attacks we can only PARTLY answer -- state these as limitations

**1. The multi-field gate's amount discrimination is verified by construction,
not on live data.** exp7 found that every agent using the poisoned amount had
also fetched the web, so "poisoned amount" and "touched an untrusted channel"
were perfectly confounded. The fix was validated on hand-built cases. The
discriminating episode -- fetch the web, then use the CORRECT amount -- still
does not occur in the live data. A reviewer can say the live evidence for that
mechanism is absent, and they are right.

**2. exp1/exp2 decompose ASR into a measured propensity and a computed gate
verdict.** Defensible and more precise than sampling, but it is a design choice,
and only exp7 and exp8 run the gate end to end.

**3. AgentDojo endorsement granularity.** We endorse every canonical token of
length >= 3 in the user's query. Generous on purpose -- a narrower extractor
would look like tuning -- but it is a choice, and a reviewer can argue either
that it is too loose (endorsing incidental tokens) or too tight (missing values
the user implied). The sensitivity of the AgentDojo numbers to this threshold is
not yet swept.

**4. claude-opus-5 is 19.9% provider-filtered.** Its per-model numbers rest on
the surviving cells, and the filtering is scenario-selective rather than random,
so its coverage is biased toward payment-redirect cases. Reported, not fixable
by us.

**5. The obfuscations in exp6 are ours.** Seven encodings is not the space of
encodings. A reviewer can always propose an eighth. The structural argument --
that the allow-list is indifferent to encoding -- does not depend on the list,
but the empirical decode rates do.

**6. TLC does not scale.** `tiered` verified to 4 slots; 5 slots, 3 values and
3 domains time out. The unbounded claim rests entirely on the SMT proof, and the
paper must say so rather than implying TLC scaled.

## D. Attacks we CANNOT currently answer

**1. Endorsement extraction from unstructured trusted output.** The allow-list
requires trusted channels to endorse STRUCTURED values. exp6's `prefix` case
fails precisely because the endorsement was recorded on prose. Real registries
return prose. We have not measured extraction error, and the guarantee inherits
it. This is the honest successor to v1's value-attribution gap: narrower, but
real.

**2. Persistent misbinding.** exp4 shows M5' degrades to origin-binding under a
permanently mislabelled channel. We propose binding attestation as the answer and
have not built or measured it.

**3. Adaptive attacks against the allow-list itself.** exp6 attacks value
ENCODING. It does not attack the endorsement mechanism -- e.g. inducing a trusted
registry to state an attacker-chosen value through a legitimate workflow. No
experiment covers that.

**4. No human study of the confirmation burden.** The confirmation rate is
computed from a workload model, not observed with users.

## E. Rules we are holding ourselves to in the write-up

1. Never present a by-construction number as an empirical finding. Section A is
   the checklist.
2. Every rate names its denominator and lists what was excluded and why.
3. Provider filtering, truncation and malformed actions never count as the model
   resisting.
4. Where a reading overrode the automated bucket, the count is reported (49 of
   1308 in exp1).
5. Every limitation in sections C and D appears in the paper, not only here.
