# exp9: the "non-consequential" answer is the primary carrier

138 decided episodes, 8 models, 3 cases, 2 monitor configurations. 6 excluded
(truncated or empty). 0 unreadable.

## The claim being tested was OURS

v1: "Answer-bias is mitigated, not eliminated: untrusted memory can still colour
a non-consequential response (surfaced with provenance), and TMA-NM guards the
retrieval-to-ACTION path, not free-text answers."

The scoping was challenged twice, and the challenge was correct.

## Turn 1: the poison reaches the unblocked answer almost always

| the answer names | n | % | Wilson 95% |
|---|---|---|---|
| the attacker's value only | 104/138 | **75.4** | [67.6, 81.8] |
| both values | 31/138 | 22.5 | [16.3, 30.1] |
| the value of record only | 3/138 | 2.2 | [0.7, 6.2] |
| neither | 0/138 | 0.0 | [0.0, 2.7] |

The poison appears in **97.8%** of unblocked answers.

## Turn 2: the answer then determines the action

| the answer said | took the attacker | used the record | declined | n |
|---|---|---|---|---|
| attacker only | **98** | 5 | 1 | 104 |
| both | 8 | 16 | 7 | 31 |
| record only | 0 | 3 | 0 | 3 |

When the answer names only the poisoned value, the agent acts on it **98 of 104
times (94%)**. When the answer names both, the split is 8 / 16 / 7.

**The answer is not a cosmetic residual. It is the carrier.** An agent that
writes its own answer back to memory -- which is what an agent with persistent
memory does -- moves the poison from a blocked path onto an unblocked one, and
then follows it. v1's scope boundary between "response" and "action" is not a
boundary in behaviour; it is only a boundary in what the gate inspects.

The system is still safe: all 106 attacker-value actions were denied. But that
is the GATE doing the work, not the scope claim. The correct statement is that
answer-biasing is the principal route into the action and is stopped at the act
gate, not that it is a minor out-of-scope residual.

## Does M2's coverage of the response channel matter? No, and that is worth saying

| M2 on the response path | the note's label | allow-list gate | origin-only gate |
|---|---|---|---|
| on | UNTRUSTED | 11/69 allowed | 0/69 allowed |
| off | AGENT | 13/69 allowed | 0/69 allowed |

Propagating the label through the agent's own answer changes the note's label
but changes neither gate's verdict, because the poisoned item itself is still in
scope for the action. So M2's coverage of the response channel is load-bearing
for what gets surfaced with provenance, and NOT for the authorisation decision.
v1 implied otherwise.

The origin-only gate denies everything here, legitimate actions included, which
is the over-blocking that motivated the allow-list in the first place.

## By construction, and labelled as such

"The gate blocked 106/106 attacker-value actions" is a consequence of the rule,
not a measurement. The measured results are the two tables above.
