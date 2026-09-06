
## D13 — a paper table drifted from the data, and nothing checked it

**Found:** while packaging the release, 2026-09-04.

**What was wrong.** Table `tab:longitudinal` reported n = 60, 60, 59, 57 and
attack rates 98.3 / 98.3 / 98.3 / 96.5. Re-deriving it from
`results/exp3_t3_1m.rows.jsonl` gives n = 62, 63, 63, 63 and 98.4 / 98.4 / 98.4
/ 96.8. No subset of the model roster reproduces the printed denominators, so
the table came from an earlier and smaller exp3 run and was never refreshed.

**Why nothing caught it.** `verify.py` ran `review3.py` and checked that it
exited cleanly. `review3.py` printed a pooled table over all eight models. The
paper printed a seven-model table. The two were never compared, and no code
anywhere computed the split the paper actually used.

**What it would have caused us to report.** The conclusion is unchanged: the
intervals overlap throughout under both versions, so accumulated history still
buys nothing. The cost was to precision and to the artifact's central claim that
every number is re-derivable, which was false for this table.

**Fix.** `review3.py` grew `PAPER_LONGITUDINAL` and `check_paper_table`, which
recompute the printed cells and compare them. `score.py` grew the same guard for
the per-model propensity table. `verify.py` asserts both marker lines, so a
future drift fails the reproduction script rather than surviving into a
submission. The propensity table was checked at the same time and matched every
cell.

**Second finding from the same pass.** Reporting only seven models hid the one
model that behaves differently. Claude Opus 5 declines all nine payments at zero
prior sessions, with complete, reasoned replies that name the unverified banking
change as a fraud pattern. Its exclusion is justified, because the provider
returned an empty content-filtered reply for 11 of its 36 attempts and those
removals fall unevenly across history lengths, but dropping it silently was
wrong. It now appears beside the seven with its scorable denominator shown, and
the paper states that no trend can be read from it.

**Third finding.** `logs/STUDY_MANIFEST.txt` declared that anything unlisted was
"excluded from every reported number", while listing only the exp1 transcripts.
The exp3, exp6, exp7 and exp9 transcripts back reported numbers and were
unlisted, so the manifest's own statement was false. It is now split into a
propensity corpus (section A, which alone may feed exp1 numbers) and the rest of
the released evidence (section B), with both consumers taught the difference so
that widening the manifest cannot widen the exp1 denominator.

**Fourth finding.** `exp3_t3_1m.jsonl` carries 2 unparseable lines out of 1152,
from two worker processes briefly writing one transcript. The scored rows are
complete: all 576 cells of the 8x4x2x3x3 grid are present with no duplicate and
no gap, and the reported numbers come from the rows. Two raw replies are not
recoverable from the log. This is now stated in the manifest and asserted by
`verify.py` as an exact expected count, so any further corruption fails.

## D14 — the implementation and the machine-checked model disagreed on the one predicate the theorem rests on

**Found:** 2026-09-05, during the pre-flight for experiment 11, before any money
was spent on that run.

**What was wrong.** `Monitor.independent_vouchers(value, supporting)` took a
value, documented itself as returning "trusted-labelled items that assert
`value`", and never read the argument. Its body filtered on origin and collapsed
by trust domain, and nothing checked that an item carried the value at all. Any
two trusted items in the supporting set therefore corroborated any value
whatever, including a value nothing in memory mentioned:

    authorize("ATTACKER-999", [two trusted items about NORTHWIND-AP],
              tier=HIGH)  ->  True

**Why this one matters more than the others.** The sufficiency theorem says a
gate admitting an action only when k distinct trust domains vouch *for its
value* satisfies the security property. The TLA+ and Z3 encodings quantify over
`vouches(d, v)` explicitly and never had the defect. The Python monitor dropped
the `v`. So the artifact that a reviewer can run and the model that carries the
proof had drifted apart on precisely the predicate the proof is about, while
every test still passed.

**Why nothing caught it.** Every experiment already in the study passes a narrow
supporting set, built so that each item asserts the value under test. Under that
input the correct and the incorrect implementations agree on every call. The
defect is only reachable when the supporting set contains a trusted item about
something else, which is what a real deployment passes and what experiment 11
was about to pass for the first time.

**What it would have caused us to report.** Experiment 11 would have shown the
gate admitting the attacker's account in every cell of the head-to-head, across
all four published pipelines and all three defense configurations. The pre-flight
check "the gate DENIES the attacker's value" was written to catch exactly this
and did. A second check, "the gate ADMITS the legitimate value", caught a
separate and milder problem in the same pass: a high-tier origin rule on the
invoice *amount* denies a legitimate payment, because an invoice amount
genuinely does arrive on an untrusted channel. That is now reported as a measured
utility cost rather than silently avoided.

**Blast radius on published numbers: none.** The fix was applied and every
deterministic experiment re-run. `exp10_restored.json` is byte-identical up to
timing, the propensity and longitudinal tables still match, and the full offline
suite passes. One test had to be corrected rather than the code: `test_m5p.py`
asserted "the old value is still licensed" while supporting the call with a
change notice that asserted only the *new* value, so it had been passing because
of the defect. Its scenario now holds both the standing record and the change
notice, which is the realistic state.

**Fix.** `Monitor.asserts(item, value)` compares canonical forms, the same
canonicalisation `history_of` already used so that a legitimately reformatted
identifier still matches. `independent_vouchers` now filters on it.
`test_vouchers.py` is a dedicated regression file, wired into `verify.py`,
covering the counting, the domain collapse, the untrusted case, the empty value,
and the two gate decisions that depend on it.

**The general lesson, which is the one worth carrying.** A machine-checked model
does not certify the code beside it. The two agree only where something forces
them to, and here nothing did. Where a proof and an implementation share a
predicate, that predicate needs a differential test whose inputs distinguish the
correct definition from a plausible wrong one. Every input the study already had
failed to distinguish them.
