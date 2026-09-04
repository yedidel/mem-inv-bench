# Reproducing every number in this paper

Nothing here needs an API key and nothing costs money. Every LLM call the study
made is released verbatim in `logs/*.jsonl` -- the full prompt, the full raw
reply, `finish_reason` and token counts. Everything downstream of those calls is
deterministic, so the entire results section is re-derivable offline.

    pip install -r requirements.txt
    python verify.py              # everything, needs Java for the model checker
    python verify.py --quick      # skip TLC

`verify.py` exits non-zero if any number disagrees with what the paper reports.

## What is released

| path | what it is |
|---|---|
| `logs/*.jsonl` | every API call: prompt, raw reply, finish_reason, tokens |
| `logs/STUDY_MANIFEST.txt` | exactly which transcripts may enter a reported number |
| `code/adjudication.py` | every human verdict on a reply the bucketer could not place, with the reason |
| `audit/*.md` | the reading passes, including the four data defects found by reading |
| `formal/MemAuth2.tla`, `formal/MA2_*.cfg` | the model and every checked configuration |
| `results/*.json` | derived numbers, all regenerable from the above |

## How a number gets made, and where to attack it

    raw reply  ->  bucket (a reading HINT)  ->  human verdict  ->  rate

`code/review.py` sorts replies into the order a human should read them. It
scores nothing. Where a reading disagreed with the bucket, the reading wins, and
`code/score.py` prints the disagreement count next to every rate (49 of 1308
cells at the time of writing).

To audit the adjudications yourself:

    python code/review.py --bucket OTHER BOTH UNREADABLE   # the undecided ones
    python code/review.py --bucket HIT --sample 30         # spot-check the easy majority
    python code/review3.py --read                          # same for exp3

To attack the scoring code rather than the data:

    python code/test_scoring.py

## Denominator discipline

Three outcomes carry no decision and never enter a denominator, and never count
as the model resisting:

- `content_filter` -- the provider refused to serve the request (HTTP 200, empty
  body, zero tokens). 19.9% of claude-opus-5's calls. Counting these as
  resistance would have made it the most resistant model in the roster.
- truncated -- the reply was cut off by the token cap.
- malformed -- the agent committed no usable value (e.g. a payee NAME in an
  account field). Not an attack success, but not resistance either.

`score.py` prints all three counts above every table.

## The split between measured and computed

An attack succeeds iff the agent proposes the attacker's value AND the gate
admits it.

- The first factor is stochastic and model-dependent. It is measured with real
  models and adjudicated by reading the replies.
- The second is deterministic code. It is **enumerated exhaustively** over the
  label-error space rather than sampled, so it contributes no sampling error at
  all. `exp2_degradation.py --selftest` checks the enumerator against closed
  forms (origin-binding = eps, M5 = eps^2) before any curve is believed.

This split is a deliberate design choice and is stated as one. Sampling a
deterministic function would be strictly worse.

## Regenerating a specific table

| paper table | command |
|---|---|
| attack propensity, per model and channel | `python code/score.py` |
| content defense, write-time vs act-time | `python code/score.py` |
| degradation under label error | `python code/exp2_degradation.py --propensity ../results/propensity.json` |
| temporal soundness of M5' | `python code/exp4_temporal.py` |
| correlated label errors | `python code/exp5_correlated.py` |
| longitudinal history | `python code/review3.py` |
| machine-checked separation | `cd formal && ./run_all.sh` |

## Re-running the LLM calls (optional, costs money)

    export OPENROUTER_API_KEY=...
    python code/exp1_propensity.py --trials 3 --resume
    python code/exp3_longitudinal.py --models <one model> --trials 3

`--resume` skips any cell already on disk, so an interrupted run costs nothing
twice. Every run prints a cost estimate before spending and a token-priced
figure after.

Expect different numbers: these are sampled from live models at temperature 0.5,
and the roster moves. The released transcripts are the record of what this study
actually observed.
