# Handoff prompt — memory-invariants v2, TOPS submission

Paste this whole file as the opening prompt of the next session.

---

## Context you need before touching anything

The paper `Securing LLM-Agent Long-Term Memory Against Poisoning` was rejected by
IEEE TDSC (TDSC-2026-06-2602). We are rewriting it as a new paper for **ACM TOPS**
in a new directory (`v2/`), so old and new findings never mix. The v1 material at
the repository root stays untouched.

**The title does not change.** The existing arXiv version has citations, and a
changed title (or subtitle) makes Google Scholar treat it as a different paper.

### Standing rules from the user, all of them binding

1. **Read every experimental result yourself.** Never conclude from code, regex,
   or a rule. A deterministic judge may run for scale, but it is only trusted
   where a reading agrees with it. (`/score-model-replies` encodes this.)
2. **0% and 100% are suspect until verified.** Every extreme cell gets its raw
   replies read before it is quoted.
3. **Estimate cost before every paid run and report actual cost after.** Key is
   `OPENROUTER_API_KEY_TAL` (already in the environment). Spend so far **$35.86
   of $200**; `python -c "import driver; driver.credits()"` from `v2/code`.
4. **Inspect the code for failure points BEFORE running, not after.** This was
   the user's sharpest correction: "you learn there's a bug only after it
   happens... inspect the code like a professional and locate the failure points
   in advance." The pre-flight discipline (`test_h2h.py`) is the pattern; it paid
   for itself by catching a real soundness bug before any spend.
5. **Persist run output during the run** so a mid-run failure loses nothing. All
   experiments checkpoint per row and support resume.
6. Reply to the user **in Hebrew**. The paper and all artifacts stay English.
7. Operating rule adopted from fourteen instrumentation defects:
   **a number whose cause has not been traced is not evidence.**

### A phrasing trap to avoid

In a Hebrew report I wrote "השער חסם 0 מתוך 109" when the data said the gate
**admitted** none, i.e. it blocked all 109. That reads as the exact opposite and
the user reasonably concluded the attack had fully succeeded. When reporting a
gate result in Hebrew, say **"התיר X מתוך Y"** or **"חסם את כל Y"**. Never phrase
an admission count as a blocking count.

---

## Current state, verified

- **Paper**: `v2/paper/tops.tex`, single file, `acmart`/`acmsmall`, separate
  `refs.bib` (39 entries). **24 pages of 35.** `bash v2/paper/build.sh` reports
  0 TeX errors, 0 undefined references, 0 overfull hboxes. Use that script, not a
  bare `pdflatex` plus a grep for "undefined" — two malformed tables once produced
  89 TeX errors while the page count and undefined count both looked clean.
- **Verification**: `python v2/verify.py --quick` exits 0 and runs eleven steps,
  including `check_manuscript.py`, which makes the manuscript's own stated numbers
  an input to the check.
- **Git**: `release_github/` is the clone of `github.com/yedidel/mem-inv-bench`.
  Local HEAD `e947fe3`, origin at `8b8e111`. **One commit is unpushed.** Working
  tree clean. Do not push without asking.
- **Hugging Face**: `release_hf/` is a staging directory, **not** a git repo, 36 MB,
  47 transcripts. It needs a real upload (`huggingface-cli upload`, needs a token
  we do not have) and the user does that. Ask before assuming it is current.
- Artifact links in the paper point at the same two URLs the earlier preprint
  used, deliberately, so old links still resolve.

---

## What remains, in the order I would do it

### 1. Phase 2b of `/paper-review` — reverse-outline flow audit (highest value)

Not yet run, and it is the phase that catches text passing every grep while still
reading as machine-written. Run it over the whole paper, not a subset:

- one-sentence summary of every paragraph, then read the chain alone
- P1.14 promise audit, P2.6 catalogue cadence, P2.7 asserted-relation filler,
  P2.8 consistent framing vocabulary
- the multi-reader cross-check protocol in the skill wants replication: several
  agents with an identical mandate, two-of-three agreement, then verify each
  finding yourself against the quoted lines

**Only spawn subagents if the user asks.** Otherwise do it inline.

Phase 1 greps are clean except items I judged false positives and left: two uses
of "genuinely" that carry a real contrast, five `\.0` values that are exact
(`50.0\%` is exactly 55/110, `1.0\times` is exactly parity), and `acmauthoryear`
which is a `\citestyle` argument, not a citation.

### 2. Phase 5 — citation-existence check

Verify every one of the 39 `refs.bib` entries resolves to a real paper. Several
are 2026 preprints. 35 BibTeX warnings remain and are cosmetic (conference papers
with no page numbers); do not invent page numbers to silence them.

### 3. Mem0 production backend — the last item lost from v1

I told the user this needed an external installation. **That was wrong, and I
corrected it.** Everything is installed: `mem0` 2.0.6, `sentence-transformers`
5.6.0, `qdrant-client`. **v1 already ran it successfully** — `code/results_mem0.json`
records ASR 50% undefended versus 0% with the defense, utility 95/96 both ways,
six models, $0.30.

The remaining work is a **port, not an installation**: v1's `code/memory_mem0.py`
implements v1's `MemoryBackend` interface, and v2's monitor is `tma.py`'s
`Monitor`, which is a different shape. Port the adapter, pre-flight it the way
`test_h2h.py` pre-flights exp11, estimate, then run. Expect well under $1.

What it buys: the paper currently models eviction and consolidation formally and
demonstrates neither on a real store. Mem0 rewrites content during consolidation,
so it is the direct test that labels survive a store that rewrites what it holds.

### 4. Close the remaining audit items

`v2/audit/FINAL-OBJECTION-CONTROL.md` stands at 24 closed, 4 partial, 5 open.
Several "open" rows are stale and now done — the bibliography pass, and the
"figures, captions, structure" row (the paper now has one figure). Re-audit the
file against the current paper rather than trusting its rows.

Genuinely still partial:
- no drift detector for channel compromise (quantified, not remedied — this is a
  deliberate scope boundary and should stay one)
- no partial-monitor-compromise experiment
- consolidated ablation exists now (`tab:ablation`); confirm the row is stale

### 5. Re-sync and hand off the artifacts

After any change: `bash v2/paper/build.sh`, `python v2/verify.py --quick`, then
copy into `release_github/v2/` and `release_hf/v2/`, re-run the secret sweep
(`grep -rlIE "sk-or-v1-|hf_[A-Za-z0-9]{20}"`), commit, and **tell the user what is
unpushed rather than pushing.**

---

## Things that are done, so you do not redo them

- exp1 propensity (8 models, 997 decided cells, 79.6%), exp2 exact degradation
  enumerator, exp3 longitudinal, exp4 temporal, exp5 correlated errors, exp6
  attribution, exp7 multi-turn, exp8 AgentDojo, exp9 boundary, exp10 restored
  measurements (cost vector, threshold sweep, lineage defaults, ablation)
- **exp11 head-to-head** against four published pipelines plus a whitebox
  adversary: 768 episodes, $2.23 including a 13-cell top-up. Gate admitted 0 of
  109 proposed attacks and all 460 legitimate actions. Whitebox is not measurably
  better than a plain cover story (19.8% vs 18.2%, overlapping intervals) — a
  genuine null result worth keeping as a null result.
- attack-class breakdown (`tab:class`): 49.3% data exfiltration to 97.6%
  procurement redirection, a spread wider than the per-model one
- the paper's one figure (`fig:independence`), inline pgfplots
- 21 dropped v1 references restored, related-work section written
- arXiv bib entries converted from `@article` to `@misc` with `eprint`

## The fourteen instrumentation defects

`v2/audit/instrumentation-defects.md`. Two are worth remembering because they are
categories, not incidents:

- **D13**: a paper table drifted from its data because the verification script ran
  the analysis without comparing its output to what the paper printed. Fixed by
  holding the published cells as literals in `score.py`, `review3.py` and
  `check_manuscript.py`.
- **D14**: `Monitor.independent_vouchers` took a value, documented itself as
  returning the trusted items asserting it, and never read the argument, so any
  two trusted items corroborated any value at all. The TLA+ and Z3 encodings
  quantify over `vouches(d, v)` explicitly and never had the defect. **The
  implementation and the machine-checked model had drifted apart on the one
  predicate the sufficiency theorem rests on, and every test still passed**,
  because every supporting set the study had built contained only items asserting
  the value under test. No published number moved; all were re-derived to
  establish that. `test_vouchers.py` guards it.

The general lesson, now in the paper: a machine-checked model does not certify the
code beside it. Where a proof and an implementation share a predicate, that
predicate needs a test whose inputs distinguish the intended definition from a
plausible wrong one.

## One tooling note that will save you time

Bash heredocs in this environment silently eat backslashes: `\\n` in a quoted
heredoc arrives as a newline, and `\\` in LaTeX arrives as `\`. That corrupted two
tables and several Python patches. **Write Python patch scripts with the Write
tool** to the scratchpad and run them, or use raw strings and verify afterwards.
