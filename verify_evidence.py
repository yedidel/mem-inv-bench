#!/usr/bin/env python3

"""Run offline evidence checks without model-provider calls.



Checks cover transcript inventory, monitor tests, exact enumerators, scoring,

numeric manuscript tables, and the threshold-two inductive proof. They do not

validate natural-language labels, recover dependency provenance, repeat live

benchmark calls, or measure deployment utility. Use --quick to skip TLC.

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

        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace",

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

    run("reported numeric values agree with the data", [py, "validate_results.py"], CODE,
        must_contain="REPORTED VALUES MATCH THE DATA")
    run("recovered benchmark package", [py, "audit_table11_provenance.py"], CODE,
        must_contain="TABLE 11 PACKAGE EVIDENCE VERIFIED")
    run("scoring-code tests", [py, "test_scoring.py"], CODE,
        must_contain="ALL SCORING TESTS PASSED")
    run("atomic local dispatcher", [py, "audit_atomic_dispatch.py"], CODE,
        must_contain="ATOMIC DISPATCH AUDIT PASSED")
    run("recovery authority boundary", [py, "audit_recovery.py"], CODE,
        must_contain="RECOVERY BOUNDARY VERIFIED")
    run("frozen recovery study", [py, "analyze_recovery.py"], CODE,
        must_contain="RECOVERY EVIDENCE VERIFIED")
    run("original CaMeL calibration", [py, "analyze_camel.py"], CODE,
        must_contain="CAMEL CALIBRATION VERIFIED")
    run("replay matching boundary", [py, "audit_replay_match.py"], CODE,
        must_contain="REPLAY MATCH BOUNDARY VERIFIED")
    run("controlled and external evidence", [py, "analyze_extension.py", "--external"], CODE,
        must_contain="EXTENSION EVIDENCE VERIFIED")
    run("experiment source and transcript integrity", [py, "audit_extension_integrity.py"], CODE,
        must_contain="EXTENSION INTEGRITY VERIFIED")


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



    run("exact scoped authorization", [py, "audit_authorization_boundary.py"], CODE,

        must_contain="AUTHORIZATION BOUNDARY VERIFIED")

    run("unbounded threshold-two proof", [py, "verify_induction.py"], FORMAL,

        must_contain="INDUCTIVE OBLIGATIONS VERIFIED")

    for script in ("test_attribution.py", "review6.py", "review7.py", "review9.py", "review11.py"):

        run(script, [py, script], CODE)



    run("complete-action contract", [py, "audit_action_authorization.py"], CODE,
        must_contain='"mismatches": 0')
    run("single-use abstract approval", [py, "verify_auth_consumption.py"], FORMAL,
        must_contain='"no_second_user_bypass": "unsat"')

    if a.quick:

        print("TLC NOT RUN (--quick); unbounded SMT obligations are checked above.")

    if not a.quick:

        run("finite model configurations", [py, "verify_tlc.py"], FORMAL,

            must_contain="TLC CONFIGURATIONS VERIFIED")



    print("\n" + "=" * 78)

    if FAILURES:

        print("VERIFICATION FAILURES:")

        for f in FAILURES:

            print("  - " + f)

        sys.exit(1)

    print("OFFLINE CHECKS PASSED -- see documented coverage and unverified "

          "deployment assumptions.")





if __name__ == "__main__":

    main()

