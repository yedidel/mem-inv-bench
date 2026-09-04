# Status of every reviewer objection, honestly scored

CLOSED = a reviewer re-reading this would have no complaint left.
PARTIAL = materially improved but a determined reviewer can still push.
OPEN = not addressed.

## Reviewer 1 (Reject)

| # | objection | status | evidence |
|---|---|---|---|
| 1 | parameter-independence hand-waved, not mechanized | **CLOSED** | `formal/unbounded.py`: the inductive step is discharged by Z3 over UNINTERPRETED sorts, so it holds for every cardinality of slots, values and domains. Base case and non-vacuity checked too. |
| 2 | no operational detection/recovery for a compromised channel | PARTIAL | exp2/exp4/exp5 quantify the degradation; no detector built |
| 3 | no precise semantics for combining multiple input origins | **CLOSED** | `Monitor.derive` is an explicit lattice meet; attribution is now an allow-list over canonical forms, measured in exp6 |
| 4 | malleability tied to three specific laundering channels | **CLOSED** | adversary quantified over an arbitrary content/edge mutation class |
| 5 | content judge not justified as the strongest instance | **CLOSED** | two instantiations measured per-model; write-time is the stronger one |
| 6 | 0% is just a deterministic blocking rule | **CLOSED** | no 0% headline; a measured trade-off surface replaces it |
| 7 | ablation predictable, no nontrivial insight | PARTIAL | M4 is load-bearing via M5'; exp9's M2 ablation is a NEGATIVE result about our own mechanism; still no consolidated ablation table |
| 8 | theory-benchmark correspondence true by construction | **CLOSED** | content detection collapse 87%->17% is measured, not stipulated |
| 9 | multi-turn and Mem0 limited in scope | **CLOSED** | exp7 runs the gate end to end in a real tool-using loop; exp8 runs it on AgentDojo |
| 10 | value-attribution gap; guarantee does not extend to black-box | **CLOSED** | exp6: v1's deny-list blocks 16.9% of successful decodes, the allow-list blocks 100%, with the utility cost measured and one case failing openly |
| 11 | important references missing | **OPEN** | not started |

## Reviewer 2 (Major revision)

| objection | status | evidence |
|---|---|---|
| A1 never tested; what happens under partial/missing labels | **CLOSED** | exp2 (exact degradation), exp4 (transient vs persistent), exp5 (correlated) |
| "0% reads like a discovery, is a restatement of the design" | **CLOSED** | reframed throughout; the zero is stated as a design consequence |
| best numbers come from the setting where the hard part is assumed | **CLOSED** | channel labelling is end-to-end; value attribution is now measured against seven obfuscations |
| utility claim rests on scenarios where 2 vouchers always exist | **CLOSED** | M5' costs quantified; confirmation is once per payee-account pair |
| preprint-heavy bibliography | **OPEN** | writing phase |
| novelty incremental (two-man rule in a new setting) | IMPROVED | T2, M5', and M5's characterised failure modes are new results, not a transplant |
| figures, captions, Section VI overload | **OPEN** | writing phase |

## Reviewer 3 (Reject)

| objection | status | evidence |
|---|---|---|
| origin-labeling oracle assumed away | PARTIAL | quantified rather than eliminated, which is the honest ceiling |
| formal model too small (3 slots, 2 sessions, k=2) | **CLOSED** | the SMT proof has no model size at all; TLC remains as a cross-check |
| extension to unbounded is a manual argument | **CLOSED** | see R1.1 |
| security predicate mirrors the authorization rule | **CLOSED** | predicate is semantic; eviction/consolidation stop the gate recomputing it |
| adversary restricted to three transformations | **CLOSED** | quantified over a class |
| cross-agent shared memory excluded | **CLOSED** | machine-checked unbounded: safe iff peers are not counted as trusted endorsers; counting them violates the invariant at every cardinality |
| non-consequential response manipulation out of scope | **CLOSED** | exp9 measures it: the poison reaches 97.8% of unblocked answers and the agent then acts on it 94% of the time. Our own scope claim was wrong and is being rewritten |
| consequential/non-consequential boundary ambiguous | **CLOSED** | exp9: the boundary is real for the GATE and not for behaviour; stated that way |
| primary evaluation assigns authority using monitor origins | **CLOSED** | channel layer with HMAC; no ground-truth field downstream |
| value-attribution gap for black-box systems | **CLOSED** | exp6 |
| tamper-evident log is auditability, not prevention | **CLOSED** | M4 carries the temporal-independence evidence; `m4=False` disables M5' |
| experiments should test labelling, attribution, policy and partial-compromise failures | PARTIAL | labelling (exp2/4/5) and attribution (exp6) done; partial monitor compromise not yet |
| title, structure, terminology, phrasing | **OPEN** | writing phase |

## Tally (after the unbounded proof, exp6-exp9 and AgentDojo)

22 closed, 4 partial, 5 open.

The 5 open items are: missing references, preprint-heavy bibliography, figures
and captions, Section VI structure, and title/terminology -- all of which belong
to the writing pass, which has not started. **No open item is of the form "the
result does not hold".** That category, which is what sank v1, is now empty. The open items are concentrated in two places:
the writing pass (which has not started) and two technical gaps.

## The two technical gaps that matter

**1. Value attribution is the same circularity, one level down.**
The whole guarantee assumes the monitor knows WHICH retrieved value drove the
action. v1 used text matching and admitted it was evadable. v2 has not addressed
it either: the harness still tells the monitor which items support the value. A
reviewer who asks "how does the monitor know?" gets the same answer that sank
v1. This must be built and measured against an obfuscating adversary before
submission, and the measurement will produce a non-zero failure rate, which is
fine and is better than another perfect score.

**2. The unbounded proof.**
R1's lead objection. The tautology is fixed, the model is being scaled, but
"machine-checked for arbitrary slots and sessions" is still not true. Either
install TLAPS and do it, or delete every claim that gestures at unboundedness.
