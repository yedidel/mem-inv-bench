# Formal authorization checks

`verify_induction.py` checks the threshold-two inductive invariant with Z3.
It establishes the base case, invariant satisfiability, unprompted legitimate
action, and preservation under eight transitions. Content, ancestry, and
single-origin policies have action countermodels. Trusting an unendorsed peer
write also breaks the coupling invariant.

Slots, values, and domains have unfixed cardinalities. The proof does not cover
arbitrary thresholds, natural-language extraction, or a refinement of the
Python and benchmark implementations. It is an abstract authorization result.

`verify_tlc.py` checks all 15 small-model configurations (three slots, two
values, two domains, threshold two). Current run records and checked outcomes
are in `../results/tlc_validation/summary.json`. Counterexamples to the
`CanActUnprompted` diagnostic establish that legitimate actions can execute;
they are expected outcomes. The runner fails on unexpected results, missing
success markers, and abnormal process exits.
