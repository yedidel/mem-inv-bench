
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
