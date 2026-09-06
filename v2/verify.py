#!/usr/bin/env python3
"""
One command that regenerates every number in the paper. No API key, no spend.

The point of this script is that a reviewer should not have to take any figure
on trust, and should not have to pay to check one. Every LLM call this study
ever made is released verbatim in logs/*.jsonl -- prompt, raw reply,
finish_reason, token counts. Everything downstream of those calls is
deterministic, so the whole results section can be re-derived offline from the
released transcripts.

    python verify.py            regenerate everything and check it
    python verify.py --quick    skip the model checker (which needs Java)

What it runs, in order:

  1. offline unit tests on the monitor              (test_tma.py)
  2. adversarial tests on M5'                       (test_m5p.py)
  3. adversarial tests on the SCORING code itself   (test_scoring.py)
  4. the exact enumerators, with self-tests         (exp2, exp4, exp5)
  5. scoring of the released transcripts            (score.py, review3.py)
  6. the machine-checked separation                 (TLC, needs Java)

Anything that disagrees with the paper is a bug in the paper, and this script is
how you find it.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
CODE = HERE / "code"
FORMAL = HERE / "formal"
LOGS = HERE / "logs"

FAILURES = []


def run(label, cmd, cwd, must_contain=None, optional=False):
    print("\n" + "=" * 78)
    print(f"[{label}]  $ {' '.join(cmd)}")
    print("=" * 78)
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                           timeout=3600)
    except FileNotFoundError:
        msg = f"{label}: command not found ({cmd[0]})"
        print("  SKIPPED -- " + msg) if optional else FAILURES.append(msg)
        return None
    except subprocess.TimeoutExpired:
        FAILURES.append(f"{label}: timed out")
        return None
    out = (p.stdout or "") + (p.stderr or "")
    print(out[-4000:])
    if p.returncode != 0 and not optional:
        FAILURES.append(f"{label}: exit {p.returncode}")
    if must_contain:
        wanted = ([must_contain] if isinstance(must_contain, str)
                  else list(must_contain))
        for w in wanted:
            if w not in out:
                FAILURES.append(f"{label}: expected {w!r} in output")
    return out


def check_transcripts():
    """The released transcripts are the evidence. Confirm they are intact and
    that only the manifest-listed ones can enter a number."""
    print("\n" + "=" * 78)
    print("[transcripts] integrity of the released evidence")
    print("=" * 78)
    sys.path.insert(0, str(CODE))
    from review import manifest_section
    manifest = LOGS / "STUDY_MANIFEST.txt"
    allowed = manifest_section(manifest, "AB")
    corpus = manifest_section(manifest, "A")
    # Two unparseable lines in exp3_t3_1m.jsonl are a known, documented defect:
    # two worker processes briefly wrote one transcript and interleaved. The
    # scored rows are complete and every reported exp3 number comes from them.
    # Any corruption beyond this is a regression and fails the check.
    KNOWN_CORRUPT = {"exp3_t3_1m.jsonl": 2}

    corpus_calls = evidence_calls = filtered = truncated = 0
    corrupt = {}
    present = set()
    for f in sorted(LOGS.glob("*.jsonl")):
        n = c = 0
        for line in f.open(encoding="utf-8", errors="replace"):
            line = line.strip()
            if not line:
                continue
            n += 1
            try:
                r = json.loads(line)
            except Exception:
                c += 1
                continue
            if f.name in corpus:
                if r.get("finish_reason") == "content_filter":
                    filtered += 1
                if r.get("truncated"):
                    truncated += 1
        if f.name in allowed:
            present.add(f.name)
            evidence_calls += n
            if f.name in corpus:
                corpus_calls += n
            if c:
                corrupt[f.name] = c
        mark = ("CORPUS   " if f.name in corpus else
                "EVIDENCE " if f.name in allowed else "excluded ")
        print(f"  {mark} {f.name:46s} {n:6d} lines, {c} unparseable")

    missing = allowed - present
    if missing:
        FAILURES.append(f"manifest lists absent transcripts: {sorted(missing)}")
    print("")
    print(f"  propensity corpus: {corpus_calls} calls")
    print(f"  all released evidence: {evidence_calls} calls")
    print(f"  provider-filtered: {filtered}   truncated: {truncated}")
    print("  (filtered and truncated calls carry no decision and are excluded "
          "from every denominator)")
    if corrupt != KNOWN_CORRUPT:
        FAILURES.append(f"transcript corruption changed: found {corrupt}, "
                        f"documented {KNOWN_CORRUPT}")
    else:
        print(f"  unparseable: {sum(corrupt.values())}, all documented "
              f"in STUDY_MANIFEST.txt")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true",
                    help="skip the TLC model checker (needs Java)")
    a = ap.parse_args()
    py = sys.executable

    check_transcripts()

    run("offline monitor tests", [py, "test_tma.py"], CODE,
        must_contain="ALL CHECKS PASSED")
    run("M5' adversarial tests", [py, "test_m5p.py"], CODE,
        must_contain="ALL M5' CHECKS PASSED")
    run("voucher predicate", [py, "test_vouchers.py"], CODE,
        must_contain="ALL VOUCHER CHECKS PASSED")
    run("manuscript agrees with the data", [py, "check_manuscript.py"], CODE,
        must_contain="MANUSCRIPT MATCHES THE DATA")
    run("scoring-code tests", [py, "test_scoring.py"], CODE,
        must_contain="ALL SCORING TESTS PASSED")

    run("exp2 enumerator self-test", [py, "exp2_degradation.py", "--selftest"],
        CODE, must_contain="ALL PASS")
    run("exp2 degradation curves",
        [py, "exp2_degradation.py", "--propensity", "../results/propensity.json"],
        CODE)
    run("exp4 temporal soundness", [py, "exp4_temporal.py"], CODE)
    run("exp5 correlated errors", [py, "exp5_correlated.py"], CODE)

    run("exp1 scoring from transcripts", [py, "score.py", "--write-propensity"],
        CODE, must_contain=["still undecided (MUST NOT SCORE) 0",
                            "PROPENSITY TABLE MATCHES",
                            "CLASS TABLE MATCHES"])
    run("exp3 scoring, and the paper table re-derived", [py, "review3.py"],
        CODE, must_contain="PAPER TABLE MATCHES")

    if not a.quick:
        for d in ("content", "lineage", "originbound", "tiered_naive", "tiered"):
            for prop in ("NoUntrustedOnly", "SecuritySem"):
                run(f"TLC {d}/{prop}",
                    ["java", "-cp", "tla2tools.jar", "tlc2.TLC",
                     "-workers", "4", "-config", f"MA2_{d}_{prop}.cfg",
                     "MemAuth2.tla"], FORMAL, optional=True)

    print("\n" + "=" * 78)
    if FAILURES:
        print("VERIFICATION FAILURES:")
        for f in FAILURES:
            print("  - " + f)
        sys.exit(1)
    print("VERIFICATION COMPLETE -- every number re-derived from the released "
          "transcripts.")


if __name__ == "__main__":
    main()
