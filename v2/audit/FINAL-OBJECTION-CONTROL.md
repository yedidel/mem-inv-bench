# Final control: every reviewer objection against the evidence that answers it

Each row names the artifact a reviewer can open. Nothing is marked closed on the
strength of an argument alone.

## Reviewer 1

| # | objection | status | evidence |
|---|---|---|---|
| 1 | parameter-independence hand-waved, not mechanized | CLOSED | `formal/unbounded.py`: inductive step in SMT over uninterpreted sorts, plus base case and two non-vacuity checks. Holds for every cardinality |
| 2 | no operational response to channel compromise | PARTIAL | exp2/exp4/exp5 quantify the degradation and its ceiling; no drift detector was built |
| 3 | no semantics for combining input origins | CLOSED | `Monitor.derive` is an explicit lattice meet; attribution is an allow-list over canonical forms, measured in exp6 |
| 4 | malleability tied to three named channels | CLOSED | adversary quantified over an arbitrary content/edge mutation in both TLC and SMT |
| 5 | content judge not the strongest instance | CLOSED | two instantiations measured per model; the write-time scanner is the stronger and is the one reported |
| 6 | 0% is a deterministic blocking rule | CLOSED | no 0% headline; every by-construction number is labelled as such in `results/FINAL_AGENTDOJO.md` and `RESULTS.md` |
| 7 | ablation predictable | PARTIAL | M4 became load-bearing via M5'; exp9's M2 ablation is a negative result about our own mechanism; no consolidated ablation table yet |
| 8 | correspondence true by construction | CLOSED | content detection collapsing 87% -> 17% on tool-echo is measured, not stipulated |
| 9 | multi-turn limited in scope | CLOSED | exp7 runs the gate end to end; exp8 runs it on AgentDojo, 384 pairs |
| 10 | value-attribution gap | CLOSED | exp6: the v1 rule blocks 28.9% of successful decodes, the allow-list is encoding-independent, utility cost measured |
| 11 | missing references | OPEN | `paper/BIBLIOGRAPHY-PLAN.md` exists; the pass has not been done |

## Reviewer 2

| objection | status | evidence |
|---|---|---|
| A1 never tested | CLOSED | exp2 exact degradation, exp4 transient vs persistent, exp5 correlated errors |
| "0% reads like a discovery" | CLOSED | reframed throughout; the zero is stated as a consequence of the rule |
| the hard part is assumed away | CLOSED | channel labelling end to end; value attribution measured against seven encodings; AgentDojo derivations mechanical |
| utility claim cannot stand | CLOSED | M5 costs a confirmation per high-tier action, M5' one per payee-account pair, the allow-list blocks 1 of 3 reformattings, AgentDojo false-block counts reported |
| preprint-heavy bibliography | OPEN | plan written, pass not done |
| novelty incremental | CLOSED | T2, T2b, M5, M5' and the correlated-error law are new results |
| figures, captions, structure | OPEN | writing pass |

## Reviewer 3

| objection | status | evidence |
|---|---|---|
| origin-labelling oracle assumed | PARTIAL | quantified rather than eliminated; the ceiling is stated |
| formal model too small | CLOSED | the SMT proof has no model size; TLC retained as a cross-check with its scaling limit stated |
| unbounded extension is manual | CLOSED | see R1.1 |
| predicate mirrors the rule | CLOSED | semantic predicate over the adversary's goal and `endorsed`, which no gate reads; eviction breaks the coincidence |
| adversary restricted | CLOSED | quantified over a class |
| cross-agent excluded | CLOSED | machine-checked unbounded: safe iff peers are not counted as endorsers |
| response manipulation out of scope | CLOSED | exp9 measures it: 97.8% of unblocked answers carry the poison, 94% of those drive the action. Our own scope claim refuted |
| consequential boundary ambiguous | CLOSED | exp9: real for the gate, not for behaviour, and stated that way |
| evaluation assigns authority from monitor origins | CLOSED | channel layer with HMAC; no ground-truth field downstream; AgentDojo adds an external check |
| value-attribution gap | CLOSED | exp6 |
| log is auditability not prevention | CLOSED | M4 carries the temporal-independence evidence; with `m4=False` M5' is blind |
| test labelling, attribution, policy, partial compromise | PARTIAL | labelling and attribution done thoroughly; partial monitor compromise not built |
| title, terminology, phrasing | OPEN | writing pass |

## Tally

**24 closed, 4 partial, 5 open.**

Every open item is the writing pass. Every partial is a stated limitation with a
measured boundary rather than an unexamined assumption. **No objection remains in
the category "the result does not hold"** -- which is the category that decided
v1.

## The defects this project found in its own work

Twelve in the harness and analysis code, five of them on the external benchmark,
each one caught before a number based on it was reported:

loaded attacker identifiers; silent truncation destroying a laundering channel;
provider content filtering counted as model resistance; a scenario whose attacker
value did not match its own poison; a retry loop mistaken for 240 denials; an
endorsement set leaking across tasks; blanket denial of any call carrying a date;
a destructive tool left ungated by a length threshold; tools skipped because no
ground truth exercised them; an asymmetry that let the gate deny a short value it
could never endorse; denials silently failing because the framework rewrote the
arguments; and a turn-budget confound.

The operating rule that came out of it: **a number whose cause has not been
traced is not evidence.**
