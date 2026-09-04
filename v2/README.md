# v2 — artifact for the TOPS submission

This directory is the artifact for the current version of the paper. The files
in the repository root are the artifact for the earlier preprint and are kept
unchanged, so a citation that pointed at them still resolves.

## What changed from v1

The earlier version's central positive claim was checked against a property
that was syntactically the gate's own guard, so it held by propositional logic
rather than by anything the model checker established. v2 restates the property
over ground truth that no authorization rule reads, which changes what the
result says. Three consequences follow, and all three are in the numbers here
rather than in the prose:

- Origin binding, the mechanism v1 proposed, resists laundering and still fails
  the semantic property. That is a negative result about our own prior position.
- The separation is re-established over uninterpreted sorts with an SMT solver,
  so it no longer depends on a model size. v1's argument beyond three memory
  slots was English.
- The benchmark was rebuilt. v1's attacker identifiers were loaded enough that
  models refused on the string rather than on the semantics, which moved the
  headline propensity by three models out of eight.

`audit/` records twelve defects this study found in its own instrumentation,
including what each would have caused us to report.

## Layout

    code/      harness, monitor, the ten experiments, the offline test suite
    formal/    TLA+ models and configurations, and the SMT encoding
    results/   per-experiment aggregates (JSON)
    audit/     defect records and the objection control
    verify.py  re-derives every number in the paper, offline

## Reproducing

    pip install -r requirements.txt
    python verify.py --quick

`verify.py` exits non-zero if any number disagrees with the paper. It needs the
raw model transcripts, which live on Hugging Face because of their size:

    https://huggingface.co/datasets/anonymos-2321135/MEM-INV-Bench

Download `v2/transcripts/` from there into `v2/logs/`. No API key is needed and
nothing costs money; every model call is released verbatim with its prompt, its
raw reply, its `finish_reason` and its token counts.
