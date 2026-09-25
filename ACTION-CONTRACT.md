# Complete-action authorization

`ScopedGate` checks independently authorized fields. `ActionGate` checks approvals
of one complete action: schema, operation, transaction namespace and identifier,
typed field values, and policy epoch. Its HMAC-authenticated records are matched
exactly; the trusted registry supplies authority and administrative domain.

The gate checks expiry and revocation at local commit. Epoch advancement removes
outstanding approvals but preserves committed transaction identities. The clock,
registry and administrative methods are trusted. The ledger is in memory and
does not survive restart. The API does not implement interactive user approval.

## Run

The standard `python verify.py --quick` checks the contract and the SMT approval
consumption obligations in an isolated working copy. To exercise local HTTP
transport as well, use the code in that working copy:

```sh
python code/experiment_endorsement_services.py --out-dir results/service-rerun
```

The service test starts two processes listening only on `127.0.0.1`, reads fixed
approval catalogs, checks 72 trials, then stops the processes. It makes no
external calls and no model calls. Slow responses and timeouts are experimental
inputs, not production latency estimates. It uses Python's standard library.

## Evidence and scope

`evidence/action-contract-evidence.zip` contains the exact recorded contract
cases, seeded conformance traces and service trial outputs. Its manifest hashes
every payload. There are 53 boundary checks and 48 sequences of 128 steps.
The field/tuple contrast records why separately valid fields can form an
unapproved combination. Positive controls preserve the approved alternatives.

The conformance oracle represents approvals over action labels independently
of record parsing. Agreement is testing evidence, not a verified refinement of
the Python program. Three thresholds are exercised; the unbounded inductive
proof still fixes threshold two. In both formal encodings, an action consumes
its value-bound user approval; that flag is not a transaction-scoped token.

Two compromised authorities can approve a substituted action. Two local
processes and keys are not two independently administered organizations. No
external validation or production deployment is claimed.
