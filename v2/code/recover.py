#!/usr/bin/env python3

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

HERE = Path(__file__).parent


def load(path: Path):
    """Read a transcript, tolerating partial or corrupt trailing lines."""
    recs, corrupt = [], 0
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                corrupt += 1
                continue
            if "tag" in r and "model" in r and "text" in r:
                recs.append(r)
            else:
                corrupt += 1
    return recs, corrupt


def rebuild(recs):
    """Group calls into cells. A cell is (model, sid, channel) and carries a
    list of independent trials; judge_write is per-cell, propose/judge_act are
    per-trial. Trial indices from different processes are merged by position,
    so a cell may end up with more trials than any single run requested."""
    by_cell = collections.defaultdict(lambda: {"propose": [], "judge_act": [],
                                               "judge_write": [], "summarize": []})
    for r in recs:
        m = r.get("meta") or {}
        key = (r["model"], m.get("sid"), m.get("channel"))
        if r["tag"] in by_cell[key]:
            by_cell[key][r["tag"]].append(r)

    rows, stats = [], collections.Counter()
    for (model, sid, channel), d in sorted(by_cell.items(), key=lambda kv: tuple(map(str, kv[0]))):
        if sid is None:
            continue
        props, acts = d["propose"], d["judge_act"]
        jw = d["judge_write"][0] if d["judge_write"] else None
        for i, p in enumerate(props):
            m = p.get("meta") or {}
            ja = acts[i] if i < len(acts) else None
            stats["cells"] += 1
            if p.get("truncated"):
                stats["propose_truncated"] += 1
            if not p.get("ok", True):
                stats["propose_error"] += 1
            rows.append({
                "model": model, "sid": sid, "channel": channel, "trial": i,
                "family": m.get("family"), "evil": m.get("evil"),
                "good": m.get("good"), "value": m.get("value"),
                "vouchers": m.get("vouchers"), "tool": m.get("tool"),
                "memory_shown": _memory_of(p),
                "task": _task_of(p),
                "proposal_raw": p["text"],
                "proposal_finish": p["finish_reason"],
                "proposal_truncated": bool(p.get("truncated")),
                "proposal_ok": bool(p.get("ok", True)),
                "judge_write_raw": jw["text"] if jw else None,
                "judge_write_truncated": bool(jw.get("truncated")) if jw else None,
                "judge_act_raw": ja["text"] if ja else None,
                "judge_act_truncated": bool(ja.get("truncated")) if ja else None,
            })
    return rows, stats


def _memory_of(rec):
    """Recover the memory block from the prompt that was actually sent."""
    for msg in rec.get("messages", []):
        if msg.get("role") == "user" and "LONG-TERM MEMORY" in msg.get("content", ""):
            c = msg["content"]
            a = c.find("\n", c.find("LONG-TERM MEMORY"))
            b = c.find("## CURRENT REQUEST")
            return c[a:b].strip() if b > a else c[a:].strip()
    return None


def _task_of(rec):
    for msg in rec.get("messages", []):
        c = msg.get("content", "")
        if "## CURRENT REQUEST" in c:
            a = c.find("## CURRENT REQUEST") + len("## CURRENT REQUEST")
            b = c.find("\n\nDecide")
            return c[a:b].strip() if b > a else c[a:].strip()
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    path = Path(a.jsonl)
    recs, corrupt = load(path)
    rows, stats = rebuild(recs)

    per_model = collections.Counter(r["model"] for r in rows)
    per_cell = collections.Counter((r["model"], r["sid"], r["channel"]) for r in rows)
    ns = collections.Counter(per_cell.values())

    print(f"transcript      : {path}")
    print(f"records         : {len(recs)} parsed, {corrupt} unusable")
    print(f"rows rebuilt    : {len(rows)}")
    print(f"truncated       : {stats['propose_truncated']} proposals "
          f"(these are EXCLUDED from any rate, never scored as safe)")
    print(f"failed calls    : {stats['propose_error']}")
    print("\nrows per model:")
    for m, n in sorted(per_model.items()):
        print(f"  {m:32s} {n:5d}")
    print("\ntrials per cell distribution:")
    for n, c in sorted(ns.items()):
        print(f"  n={n}: {c} cells")

    out = Path(a.out) if a.out else (HERE.parent / "results" / (path.stem + "_recovered.json"))
    out.write_text(json.dumps(
        {"source": str(path), "n_rows": len(rows),
         "corrupt_lines": corrupt, "stats": dict(stats), "rows": rows},
        indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nwrote {out}")
    print("NOTE: no rate computed. Read the replies before scoring.")


if __name__ == "__main__":
    main()
