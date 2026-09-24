#!/usr/bin/env python3
"""OpenRouter experiment driver with raw response logging and completion status."""
from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from pathlib import Path

import requests

BASE = "https://openrouter.ai/api/v1"
KEY = os.environ.get("OPENROUTER_API_KEY_TAL") or os.environ.get("OPENROUTER_API_KEY")
if not KEY:
    sys.stderr.write("[fatal] OPENROUTER_API_KEY_TAL / OPENROUTER_API_KEY not set\n")
H = {"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"}

HERE = Path(__file__).parent
LOGDIR = HERE.parent / "logs"
LOGDIR.mkdir(exist_ok=True)

MODELS = [
    "openai/gpt-5.6-terra",         # OpenAI
    "anthropic/claude-opus-5",      # Anthropic
    "google/gemini-3.8-flash",      # Google
    "x-ai/grok-4.6",                # xAI
    "deepseek/deepseek-v4-pro",     # DeepSeek
    "qwen/qwen3.8-max",             # Alibaba
    "moonshotai/kimi-k3",           # Moonshot
    "meta-llama/llama-4-maverick",  # Meta
]
# Cheap panel for calibration and pilots (not a headline roster).
PILOT = ["openai/gpt-4o-mini", "google/gemini-3.8-flash", "deepseek/deepseek-v4-pro"]

PRICES = json.loads((HERE / "prices.json").read_text()) if (HERE / "prices.json").exists() else {}


def price_of(model):
    p = PRICES.get(model)
    return (float(p["prompt"]), float(p["completion"])) if p else (None, None)


def estimate(plan, label="run"):
    """plan: list of (model, n_calls, avg_prompt_tokens, avg_completion_tokens).
    Prints a per-model and total dollar estimate BEFORE spending anything."""
    tot = 0.0
    print(f"\n--- cost estimate: {label} ---")
    for model, n, pin, pout in plan:
        ip, op = price_of(model)
        if ip is None:
            print(f"  {model:32s} n={n:5d}  (no price on file)")
            continue
        c = n * (pin * ip + pout * op)
        tot += c
        print(f"  {model:32s} n={n:5d}  ~${c:7.4f}")
    print(f"  {'TOTAL':32s}        ~${tot:7.4f}")
    print("  (reasoning models can multiply completion tokens several-fold; "
          "treat this as a lower bound and watch the post-run figure)")
    return tot


def spend_so_far():
    """Token-priced spend of this process, per model. The /credits delta is too
    coarse for small runs, so this is the primary figure and credits is a
    session-level cross-check."""
    tot = 0.0
    for m, (pt, ct) in PER_MODEL.items():
        ip, op = price_of(m)
        if ip is None:
            continue
        tot += pt * ip + ct * op
    return tot

USAGE = {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0}
FINISH: dict[str, int] = {}          # finish_reason -> count
PER_MODEL: dict[str, list] = {}      # model -> [prompt_tokens, completion_tokens]
_lock = threading.Lock()
_transcript: Path | None = None


def open_transcript(run_id: str, append: bool = False) -> Path:
    """Start a JSONL transcript for this run. Every call lands here verbatim.

    `append=True` preserves an existing transcript, which is what a resumed run
    wants: the calls already paid for stay on disk and stay readable."""
    global _transcript
    _transcript = LOGDIR / f"{run_id}.jsonl"
    if not append or not _transcript.exists():
        _transcript.write_text("", encoding="utf-8")
    return _transcript


def _log(rec: dict):
    if _transcript is None:
        return
    with _lock:
        with _transcript.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


def call(messages, model, *, temperature=0.4, max_tokens=1024, tag=None, meta=None,
         retries=4):
    """One chat completion.

    Returns a dict: {text, finish_reason, truncated, ok, model, ...}. `truncated`
    is True when the model was cut off by the token cap, in which case the caller
    MUST exclude the datum rather than score it.
    """
    body = {"model": model, "messages": messages,
            "temperature": temperature, "max_tokens": max_tokens}
    last = None
    for i in range(retries):
        try:
            r = requests.post(BASE + "/chat/completions", headers=H, json=body, timeout=120)
            if r.status_code == 200:
                j = r.json()
                u = j.get("usage") or {}
                ch = (j.get("choices") or [{}])[0]
                fr = ch.get("finish_reason") or ch.get("native_finish_reason") or "unknown"
                text = ((ch.get("message") or {}).get("content") or "").strip()
                with _lock:
                    USAGE["calls"] += 1
                    USAGE["prompt_tokens"] += int(u.get("prompt_tokens", 0))
                    USAGE["completion_tokens"] += int(u.get("completion_tokens", 0))
                    FINISH[fr] = FINISH.get(fr, 0) + 1
                    pm = PER_MODEL.setdefault(model, [0, 0])
                    pm[0] += int(u.get("prompt_tokens", 0))
                    pm[1] += int(u.get("completion_tokens", 0))
                rec = {"tag": tag, "model": model, "meta": meta or {},
                       "messages": messages, "text": text, "finish_reason": fr,
                       "truncated": fr in ("length", "max_tokens"),
                       "prompt_tokens": int(u.get("prompt_tokens", 0)),
                       "completion_tokens": int(u.get("completion_tokens", 0)),
                       "ok": True}
                _log(rec)
                return rec
            last = f"HTTP {r.status_code}: {r.text[:200]}"
            if r.status_code in (429, 500, 502, 503, 524):
                time.sleep(min(2 ** i, 20))
                continue
            break
        except Exception as e:  # noqa: BLE001
            last = str(e)
            time.sleep(min(2 ** i, 20))
    sys.stderr.write(f"[warn] call failed ({model}): {last}\n")
    rec = {"tag": tag, "model": model, "meta": meta or {}, "messages": messages,
           "text": "", "finish_reason": "error", "truncated": False,
           "error": last, "ok": False}
    _log(rec)
    return rec


def gen(prompt, model, *, system=None, **kw):
    msgs = ([{"role": "system", "content": system}] if system else []) + \
           [{"role": "user", "content": prompt}]
    return call(msgs, model, **kw)


def credits():
    try:
        r = requests.get(BASE + "/credits", headers=H, timeout=30)
        if r.status_code == 200:
            d = r.json()["data"]
            tot = float(d.get("total_credits", 0.0))
            use = float(d.get("total_usage", 0.0))
            return use, max(tot - use, 0.0)
    except Exception:
        pass
    return None, None


def report_cost(use0, label="run"):
    use1, rem1 = credits()
    tok = (f"{USAGE['calls']} calls, {USAGE['prompt_tokens']}+"
           f"{USAGE['completion_tokens']} tokens")
    fin = ", ".join(f"{k}={v}" for k, v in sorted(FINISH.items()))
    print(f"[finish_reason] {fin}")
    print(f"[cost/tokens] token-priced spend this run: ${spend_so_far():.4f}")
    for m, (pt, ct) in sorted(PER_MODEL.items()):
        ip, op = price_of(m)
        c = (pt * ip + ct * op) if ip is not None else float("nan")
        print(f"   {m:32s} {pt:8d}+{ct:7d} tok  ${c:7.4f}")
    if use0 is not None and use1 is not None:
        spent = use1 - use0
        print(f"[cost] {label}: ${spent:.5f}   {tok}   balance: ${rem1:.4f}")
        return spent, rem1
    print(f"[cost] {label}: credits endpoint unavailable   {tok}")
    return None, None


def parse_json(text):
    """Best-effort JSON extraction. NEVER the last word on a reply: the raw text
    stays in the transcript and a None here means the reply must be read."""
    if not text:
        return None
    t = re.sub(r"^```(json)?|```$", "", text.strip(), flags=re.MULTILINE).strip()
    try:
        return json.loads(t)
    except Exception:
        pass
    # Extract the FIRST balanced object. A greedy `\{.*\}` spans from the first
    # brace to the last, so a reply containing two JSON objects -- which
    # gpt-5.6-terra emits routinely -- parses as nothing and the turn is scored
    # UNREADABLE. That is a harness artefact being recorded as model behaviour.
    depth, start = 0, None
    for i, ch in enumerate(t):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    o = json.loads(t[start:i + 1])
                    if isinstance(o, dict):
                        return o
                except Exception:
                    pass
                start = None
    return None


if __name__ == "__main__":
    use, rem = credits()
    print(f"OpenRouter OK. used=${use:.4f}  remaining=${rem:.4f}" if rem is not None
          else "credits endpoint returned nothing")
