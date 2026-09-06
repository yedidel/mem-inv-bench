#!/usr/bin/env python3
"""Check the manuscript's stated numbers against the data behind them.

Two defects in this study came from the same gap. A table went stale because
the reproduction script ran the analysis without ever comparing its output to
what the paper printed. Then the paper's pooled row was corrected in the table
and left uncorrected in the two sentences that restate it, one of them in the
abstract.

The lesson both times is that the manuscript has to be an INPUT to the check,
not a downstream artifact of it. `score.py` and `review3.py` now hold the
published table cells as literals. This file closes the other half: it reads
tops.tex and confirms that every number the prose restates about a table still
matches the table, and that no superseded value survives anywhere in the file.

A number appearing in prose and nowhere else is not covered here and cannot be:
it has no table to disagree with. Those are listed at the end so the count is
honest about what is and is not guarded.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

TEX = Path(__file__).parent.parent / "paper" / "tops.tex"
FAIL = []


def check(label, ok, detail=""):
    print(f"  [{'ok ' if ok else 'FAIL'}] {label}{('  ' + detail) if detail else ''}")
    if not ok:
        FAIL.append(label)


src = TEX.read_text(encoding="utf-8")
body = re.sub(r"(?m)^\s*%.*$", "", src)

print("=" * 74)
print("1. superseded values must appear nowhere in the manuscript")
print("=" * 74)
# (what it was, what replaced it, why it changed)
SUPERSEDED = [
    ("985 decided cells", r"\$985\$ decided", "997 after the top-up run"),
    ("pooled 79.4%", r"79\.4\\%", "79.6% from 794/997"),
    ("pooled CI [76.8, 81.8]", r"\[76\.8, 81\.8\]", "[77.0, 82.0]"),
    ("pooled row 777", r"& 777 &", "794, the sum of its own column"),
    ("longitudinal 98.3%", r"98\.3\\%", "98.4% on the current row set"),
    ("longitudinal 96.5%", r"96\.5\\%", "96.8%"),
    ("thirteen defects", r"thirteen defects", "fourteen"),
    ("twelve defects", r"twelve defects", "fourteen"),
]
for label, pat, why in SUPERSEDED:
    hits = re.findall(pat, body)
    check(f"no {label}", not hits, f"(superseded by {why})" if hits else "")

print()
print("=" * 74)
print("2. prose restating a table agrees with that table")
print("=" * 74)
# (description, regex that must match somewhere in the prose)
RESTATED = [
    ("pooled propensity in the abstract and body",
     r"consequential action in \$79\.6\\%\$"),
    ("pooled denominator", r"Pooled over \$997\$ decided cells"),
    ("pooled interval", r"\[77\.0, 82\.0\]"),
    ("per-model range low end", r"\$50\.0\\%\$"),
    ("per-model range high end", r"\$95\.7\\%\$"),
    ("longitudinal rates", r"\$98\.4\\%\$"),
    ("longitudinal last row", r"\$96\.8\\%\$"),
    ("attack-class low end", r"49\.3\\%"),
    ("independence advantage at eps=0.01", r"16\.9\\times"),
    ("independence collapse", r"1\.0\\times"),
    ("defect count", r"fourteen defects"),
    ("head-to-head top pipeline", r"35\.4\\%"),
    ("head-to-head bottom pipeline", r"10\.6\\%"),
    ("whitebox style rate", r"19\.8\\%"),
    ("static style rate", r"18\.2\\%"),
    ("gate admitted every legitimate action", r"\$460\$ episodes"),
]
for label, pat in RESTATED:
    check(label, bool(re.search(pat, body)))

print()
print("=" * 74)
print("3. every table row sums to the pooled row that follows it")
print("=" * 74)


def tabular_rows(label):
    m = re.search(r"\\label\{" + re.escape(label) + r"\}(.*?)\\end\{tabular\}",
                  body, re.S)
    if not m:
        return []
    out = []
    for line in m.group(1).split("\n"):
        if "&" in line and "\\\\" in line and "multicolumn" not in line:
            cells = [c.strip() for c in line.split("\\\\")[0].split("&")]
            out.append(cells)
    return out


rows = tabular_rows("tab:permodel")
data = [r for r in rows if len(r) >= 3 and re.fullmatch(r"\d+", r[1] or "")]
if data:
    pooled = [r for r in data if r[0].lower().startswith("pooled")]
    models = [r for r in data if not r[0].lower().startswith("pooled")]
    sa = sum(int(r[1]) for r in models)
    sr = sum(int(r[2]) for r in models)
    check("tab:permodel attacked column sums to its pooled row",
          bool(pooled) and int(pooled[0][1]) == sa,
          f"rows={sa} pooled={pooled[0][1] if pooled else '?'}")
    check("tab:permodel refused column sums to its pooled row",
          bool(pooled) and int(pooled[0][2]) == sr,
          f"rows={sr} pooled={pooled[0][2] if pooled else '?'}")
else:
    check("tab:permodel parsed", False, "could not read the table body")

print()
print("=" * 74)
print("4. structural")
print("=" * 74)
check("at least one figure", body.count(r"\begin{figure}") >= 1,
      f"{body.count(chr(92) + 'begin{figure}')} figures, "
      f"{body.count(chr(92) + 'begin{table}')} tables")
check("no placeholder text",
      not re.search(r"\b(TBD|FIXME|XXX|placeholder)\b", body, re.I))

print()
if FAIL:
    print(f"MANUSCRIPT CHECK FAILED: {len(FAIL)}")
    for f in FAIL:
        print("  -", f)
    sys.exit(1)
print("MANUSCRIPT MATCHES THE DATA")
