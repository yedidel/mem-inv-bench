# Independent replication checklist

The replicator should not receive API credentials or unpublished labels from the authors.

- [ ] Record operating system, Python version, and git commit.
- [ ] Run `python -m unittest discover -s tests -v`.
- [ ] Run `./reproduce_offline.sh` and retain stdout.
- [ ] Verify the pinned upstream commit independently.
- [ ] Inspect whether `tma_nm()` matches upstream semantics for the frozen categories.
- [ ] If performing a live rerun, use a new output directory and report model snapshot,
      transport, token use, Actor exposure, and every case-level action.
- [ ] Do not alter cases, labels, thresholds, or primary metrics after viewing outputs.
- [ ] Report disagreements or failed reproduction, including negative results.

Suggested statement if all offline checks pass:

> We independently verified the hashes, deterministic gateway decisions, and released
> statistics of the MEM-INV contextual/temporal extension v1. We did/did not separately
> verify its mapping to the upstream TMA-NM threat model.

