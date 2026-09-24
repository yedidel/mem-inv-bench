# Reproducing the experiments

The root README gives the offline command. Verification copies the code and
unpacks recorded evidence into a fresh work directory. The experimental runners
retain their frozen hashes. Numeric reference values are stored in `reported_values.json`. Analyses export
table fragments in the work directory only.

The evidence manifest selects the same records as the research archive. Two
malformed lines in one historical transcript are retained and explicitly counted;
its complete scored rows support the reported analysis. Unknown provider outcomes
remain unknown. Fourteen pilots are excluded from the 4,384 planned records.
Console-only local machine paths are masked, with original/public hashes recorded
in results/public-export-provenance.json. Model requests, replies and scored
scientific JSON records are otherwise preserved.

## CaMeL replay

After the quick check, its working directory contains code, vendor packages and
evidence. In a separate Python 3.12 environment, install the supplied
requirements-camel-resolved.txt from the repository root. Then run
`python code/run_camel.py --replay` from the working directory. It makes no model
calls. Compare all 256 outcome pairs, retaining the distinction between replayed
trajectories and native scores retained when dynamic output prevents exact replay.
All 51 policy stops and seven budget stops must be scored from reconstructed state.
Identical generated class declarations may be reordered; other request changes
are rejected. See code/audit_replay_match.py and the stored provenance.

## Package identities

The later experiments use source commit 089ed468cf3ed0322acc66b0211f26d9d90dbf60.
The recovered adapter installation matches the official PyPI AgentDojo 0.1.35
wheel, whose hash is recorded in results/table11-provenance.json. Five source
files differ despite the shared version label. Its wheel is inside
vendor/agentdojo-table11-recovery.zip; do not substitute it in the later runs.
The recovery is retrospective and does not recreate a historical dependency lock.

## Independent checks and labels

An independent evaluator should use a fresh checkout and environment, retain
the full verification log/report and package versions, and record all assistance
received. Passing locally is not an independent evaluation. Formal and mechanical
checks require no human labels. Interpreting ambiguous model replies or approvals
in natural documents does: independent annotators are needed to quantify whether
the author's interpretation agrees with other readers. No such agreement score
is claimed. Authored fixtures are not naturally sampled workflow documents.

Live runs require explicit provider setup, current dependencies and budgets;
they are not part of these offline commands and may produce different outcomes.
