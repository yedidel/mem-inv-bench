# Does the single-trusted-source case collapse the method?

No. But blunt M5 as first implemented was over-conservative, and the correct
answer is a three-way design choice that can now be stated precisely, with the
failure mode of each option quantified rather than asserted.

## The problem

M5 required k=2 independent trust domains for every high-tier action. A
legitimate action whose value comes from one trusted registry -- the ordinary
case -- got 0% auto-authorisation. Every such action would need a confirmation.

## Why it is not fatal: the attack is always a change

An attack must introduce a value that is not the established one. If the
adversary used the established payee there is no attack. So the
security-relevant event is always FIRST USE or CHANGE of a value, never
continued use of an established one. The corroboration requirement therefore
only needs to bind on new or changed values.

## Why an established value is genuinely corroborated

An endorsement recorded before the adversary had any influence is one the
adversary could not have manufactured. That is independence along the time axis
rather than the principal axis.

It is only sound if the history is anchored where the adversary cannot reach it.
It is read from the monitor's append-only log (M4), never from agent memory,
which the adversary can poison. `test_m5p.py` attacks this directly: ten epochs
of attacker writes to memory leave `established()` False and the action denied.

This also rescues M4. In v1 its ablation changed neither ASR nor utility, and two
TDSC reviewers said so ("contributes auditability rather than prevention", "its
role in the core security contribution appears secondary"). Under M5' it carries
the temporal-independence evidence and is load-bearing: with `m4=False`,
`established()` is blind and M5' cannot license anything.

## The confirmation burden, exactly

| history | established value | new value (the attack) |
|---|---|---|
| N=0, first payment ever | DENIED | DENIED |
| N>=1 | ALLOWED on one registry | DENIED |

So M5' charges a confirmation **once per (payee, account) pair, on first use, and
never again unless the account changes**. That is the amortised cost.

It is also, independently, the control that accounts-payable departments already
run: vendor bank-detail changes are routed for verification, and 55% of
companies verify a change by calling the vendor. M5' is not an exotic burden; it
is the existing control point, with a soundness argument attached.

## Where M5' fails, measured (exp4, exact enumeration, 4 epochs, k=2)

Two kinds of labelling failure that v1 and the literature conflate:

  TRANSIENT   a binding is wrong in one epoch (a misconfiguration that gets
              corrected, a briefly mis-issued certificate)
  PERSISTENT  a binding is wrong in every epoch (an untrusted feed permanently
              registered as a trusted API, or a compromised provider)

Adversary-optimal admission probability:

| eps | origin-bound | M5 blunt | M5' transient | M5' PERSISTENT |
|---|---|---|---|---|
| 0.01 | 1.000% | 0.059% | 0.059% | **1.000%** |
| 0.02 | 2.000% | 0.234% | 0.234% | **2.000%** |
| 0.05 | 5.000% | 1.402% | 1.402% | **5.000%** |
| 0.10 | 10.000% | 5.230% | 5.230% | **10.000%** |
| 0.20 | 20.000% | 18.080% | 18.080% | **20.000%** |
| 0.35 | 43.702% | 43.702% | 43.702% | 43.702% |

**M5' keeps all of M5's security against a transient error at near-zero utility
cost, and collapses exactly to origin-bound against a persistent one**, because
a permanently misbound channel accrues history in every epoch and the value
looks established. Temporal independence is a defense against transient
mislabelling and against nothing else.

Note also that every option converges by eps ~ 0.35: at that error rate the
adversary simply seeds more channels and collects k misbindings. No threshold
mechanism survives a sufficiently mislabelled deployment, and saying so is part
of the result.

## The three-way choice the paper can now state

| mechanism | confirmation burden | transient error | persistent error |
|---|---|---|---|
| origin-bound (all of v1) | none | ASR ~ eps | ASR ~ eps |
| M5 blunt | every high-tier action | ASR ~ eps^2 | ASR ~ eps^2 |
| M5' change-gated | once per payee-account pair | ASR ~ eps^2 | ASR ~ eps |

Recommendation: M5' paired with binding attestation, because attestation is what
turns a persistent misbinding into a detectable one, which is exactly the gap
M5' leaves open. That closes the loop with the label-drift detector.

## What this does to the paper

It replaces a claimed 0% with a characterised trade-off surface: two mechanisms,
two failure modes, one measured cost, and a stated ceiling beyond which nothing
works. That is a stronger and much more defensible contribution than v1's
"0% attack success at full utility", and it answers the reviewer objection that
the utility claim "can't stand as written".
