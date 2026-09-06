# Proposed upstream contribution (draft; not submitted)

## Title

Add an optional contextual/temporal authority extension benchmark

## Summary

This contribution adds a separately namespaced benchmark extension that asks whether
origin-bound authority composes with contextual binding, current validity, and scoped
delegation. It does not modify TMA-NM's existing scenarios, results, or claims.

The extension contains 24 prospectively frozen synthetic episodes across origin
laundering, authentic-wrong-context replay, revoked references, and legitimate scoped
delegation. Both policies inspect the same Actor proposal. TMA-NM remains the strong
origin-laundering baseline; the composed policy adds context/status enforcement.

## Why this belongs as an extension

The existing benchmark establishes non-malleable origin authority. Authentic references
can nevertheless remain origin-trusted while being used outside their issued case or
after revocation. These are orthogonal authority dimensions, so the proposed evaluation
is framed as composition rather than replacement or vulnerability disclosure.

## Reproduction

```bash
./reproduce_offline.sh
python -m unittest discover -s tests -v
```

No API key is required for verification. A direct-OpenAI live runner is optional and
explicitly distinguished from the canonical OpenRouter protocol.

## Review requests for maintainers

1. Is the mapping in `tma_nm()` faithful for the four frozen item categories?
2. Would you prefer contextual/status fields in `MemoryItem`, or an external composed
   reference monitor?
3. Should this remain an independent artifact rather than enter the canonical benchmark?

## Claim boundary

The observed controlled result is not an official leaderboard score, a natural attack
rate, or a production-safety claim. Upstream inclusion and independent execution would
be reported separately from the current author-run evidence.

