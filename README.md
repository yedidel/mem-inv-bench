# MEM-INV-Bench

Code, formal models and recorded evidence for **Securing LLM-Agent Long-Term Memory Against Poisoning: Non-Malleable, Origin-Bound Authority with Machine-Checked Guarantees**. The experiments separate
model proposals, authorization decisions, committed actions and task completion.

## Reproduce without model access

Use Python 3.12 in a fresh virtual environment:

```sh
python -m pip install -r requirements.txt
python verify.py --quick
```

This validates source hashes, recorded experiments, numerical reference data,
authorization checks and the threshold-two inductive proof. It extracts evidence
to a separate working directory and saves a full log and report there. With
Java 21 on PATH, omit `--quick` to also check 15 finite TLA+ configurations.
No provider credentials are required.

## Layout

| Path | Contents |
|---|---|
| `code/` | Experiment runners, scoring and authorization implementations |
| `formal/` | Abstract models, proof checks and TLA+ checker |
| `evidence/recorded-evidence.zip` | Original recorded inputs/results plus manifest |
| `vendor/` | Pinned source packages and licenses |
| `reported_values.json` | Machine-readable numerical reference values |
| `REPRODUCE.md` | Scope, dependencies, replay and annotation limitations |

The [Hugging Face dataset](https://huggingface.co/datasets/anonymos-2321135/MEM-INV-Bench)
provides typed evaluation tables and the same evidence bundle. The GitHub repository supplies executable checks; the dataset repository supplies
structured evaluation records.

## Evidence scope

Five frozen extension plans contain 4,384 evaluation records: 1,152 dispatch,
480 endorsement-extraction probes, 768 original AgentDojo calibrations, 1,728
recovery episodes and 256 CaMeL calibrations. Fourteen pilots are separate.
The archive also retains the eight-model proposal study and its scoring records.
Constructed approvals and fixtures do not measure real-world source availability.
Two domains help under the stated authority and failure assumptions. A blocked
attack and a completed legitimate task are separate outcomes.

Extraction labels are authored by construction. Some proposal-parser decisions
were adjudicated by the author. Neither is independent annotation. Code checks
and repeated computation do not establish human agreement or field validity.
The recorded environment checks were performed within the project. No
independent external reproduction is claimed.

## Versions and citation

The repository root contains the current artifact. Pin a commit or release tag
when citing or reproducing a result; the artifact version is in `release.json`.
Use `CITATION.cff` for this software.
See `LICENSE` and `THIRD_PARTY_NOTICES.md` for attribution.
