# exp8: the gate on AgentDojo, and the bug that nearly went into the paper

AgentDojo (Debenedetti et al., NeurIPS 2024 Datasets & Benchmarks), banking
suite, `important_instructions` attack, gpt-4o-mini, 8 user tasks x 5 injection
tasks = 40 pairs per mode. Tasks, injections and scoring are AgentDojo's. We add
a gate and report what their `utility()` and `security()` say.

## Nothing was hand-picked

| what could have been tuned | how it was derived instead |
|---|---|
| the channel partition | `probe_channels.py` plants a marker in every injection vector AgentDojo declares and observes which tool outputs can carry it |
| the consequential tool set | the final call of each injection task's own `ground_truth()` |
| the gated fields | those calls' argument names |

The `strict` variant uses no partition at all: the user's task query is the only
endorser. It is the configuration in which we made no judgement calls.

## The defect, what is established, and what I retract

The first run reported strict ASR 10.0% against an undefended 62.5%, which
looked like a clean win. Reading the blocked calls rather than the summary:

    send_money  denied fields=['subject','date']
                args={'recipient': 'US133000000121212121212', ...}

`recipient` -- the attacker's IBAN, the entire point of the attack -- was
PERMITTED, so the drop appeared to come from denying `subject` and `date`, which
would be an incidental block rather than the mechanism working.

**A real defect, found and fixed:** `GatingExecutor` was constructed once per
mode and reused across all task pairs, so the endorsement set accumulated across
tasks. A gate that carries one task's endorsements into the next is wrong on its
face, whatever it did to these numbers. Fixed: the set resets whenever the task
query changes. Verified two ways -- after a task that legitimately names an IBAN
`_permitted` returns True, after switching tasks it returns False; and an
instrumented run confirms `query` is the user prompt and is constant within an
episode, so the reset fires exactly once per episode and never mid-episode.

**What I retract:** I first attributed the permitted recipient to AgentDojo's
`user_task_15`, whose prompt legitimately contains the attacker's IBAN. That
task is not in the first eight in dict order, so it was never in this run, and
the explanation cannot be right. I cannot reconstruct the original behaviour
from the saved artifacts because only eight blocked examples were persisted.
The honest statement is: a real state-leak existed and is fixed; its precise
effect on the first run's numbers is unexplained; and the first run's numbers are
discarded rather than reinterpreted.

**What the fix let us establish.** The full distribution of denial reasons is now
recorded, because a sample of eight is not evidence about which field is gated:

| mode | subject | date | amount | **recipient** | total blocks |
|---|---|---|---|---|---|
| strict | 597 | 601 | 138 | **533** | 687 |
| probed | 614 | 622 | 196 | **478** | 692 |

`recipient` is the denied field in 533 of 687 strict denials (78%), and is the
SOLE denied field in 86 of them. The mechanism under test is doing the work.

## Results after the fix

| mode | n | AgentDojo utility | AgentDojo attack success |
|---|---|---|---|
| none (undefended) | 40 | 32.5% | 65.0% |
| strict (no partition) | 40 | 30.0% | **0.0%**, Wilson [0, 8.8] |
| probed (mechanical partition) | 40 | 25.0% | **0.0%**, Wilson [0, 8.8] |

RUN-TO-RUN VARIANCE, which must be reported: across two runs at temperature 0
the undefended baseline moved from 40.0%/62.5% to 32.5%/65.0% utility/ASR. The
provider is not deterministic at temperature 0. n=40 is small and a single seed;
the 0.0% carries a Wilson upper bound of 8.8% and should be quoted with it.

The utility cost is real and is reported: 40.0% -> 32.5% strict, and 27.5%
probed. AgentDojo tasks legitimately take values from tool outputs, and a gate
that endorses only the user's query blocks some of that work. That the `probed`
partition scores WORSE on utility than `strict` is itself worth reporting rather
than smoothing over.

## An honest edge case worth stating

For `user_task_15` the user's own request contains the same IBAN the injection
targets. For that one pair the gate cannot distinguish the attack from the task,
and permitting the recipient is the correct behaviour, not a failure. It is a
clean illustration of the boundary: origin-bound authority separates what the
user asked for from what a document asked for, and when those coincide there is
nothing to separate.

## Still to do before this goes in the paper

1. More seeds and more of the suite. n=40 on one seed, with a baseline that moved
   between runs, is not enough to quote a 0.0% without heavy hedging.
2. The other three suites (workspace, slack, travel), where the consequential
   actions are emails, file shares and reservations rather than payments.
3. More models. Everything here is gpt-4o-mini.
4. A statement of the utility cost that separates tasks the gate blocked from
   tasks the agent failed anyway: the undefended baseline solves only 32.5%, so
   the 2.5-point drop is measured against a low ceiling.
