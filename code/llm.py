#!/usr/bin/env python3
"""
OpenRouter LLM driver for MEM-INV-Bench.

Adapted from survey/benchmark/harness.py (reused OpenRouter driver + cost
tracking + JSON parsing). LLM access is OpenRouter ONLY (OPENROUTER_API_KEY).
The personal GOOGLE_API_KEY is FORBIDDEN; Gemini is reached via OpenRouter.

Every run must report cost + remaining balance (see credits()).
"""
import os
import json
import re
import sys
import time

import requests

BASE = "https://openrouter.ai/api/v1"
KEY = os.environ.get("OPENROUTER_API_KEY")
if not KEY:
    sys.stderr.write("[fatal] OPENROUTER_API_KEY not set\n")
H = {"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"}

# Lightweight usage accounting (the /credits delta is too coarse for small runs).
USAGE = {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0}
# Silent-failure guard: per-model count of empty responses (HTTP error / rate-limit /
# parse). A model with a high empty rate produced unreliable data and must be excluded.
EMPTY = {}      # model -> count of empty returns
ATTEMPTS = {}   # model -> total gen attempts


def _track(resp_json):
    u = resp_json.get("usage") or {}
    USAGE["calls"] += 1
    USAGE["prompt_tokens"] += int(u.get("prompt_tokens", 0))
    USAGE["completion_tokens"] += int(u.get("completion_tokens", 0))


def _note(model, text):
    ATTEMPTS[model] = ATTEMPTS.get(model, 0) + 1
    if not text:
        EMPTY[model] = EMPTY.get(model, 0) + 1
    return text


def empty_rates():
    """Return {model: (empty, attempts, rate)} for the silent-failure guard."""
    return {m: (EMPTY.get(m, 0), ATTEMPTS[m], EMPTY.get(m, 0) / ATTEMPTS[m])
            for m in ATTEMPTS}

# Cross-vendor frontier models, the eight-model roster used in the paper
# (override per-experiment with --models as needed).
MODELS = [
    "openai/gpt-5-chat",
    "openai/gpt-4o-mini",
    "anthropic/claude-opus-4.1",
    "anthropic/claude-sonnet-4.5",
    "google/gemini-2.5-flash",
    "meta-llama/llama-4-maverick",
    "deepseek/deepseek-chat",
    "qwen/qwen3-235b-a22b",
]


def gen(prompt, model, temperature=0.7, max_tokens=600, system=None, retries=4):
    """Single-turn completion. Returns stripped text, or "" on hard failure."""
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    body = {"model": model, "messages": messages,
            "temperature": temperature, "max_tokens": max_tokens}
    last = None
    for i in range(retries):
        try:
            r = requests.post(BASE + "/chat/completions", headers=H, json=body, timeout=60)
            if r.status_code == 200:
                j = r.json()
                _track(j)
                return _note(model, (j["choices"][0]["message"]["content"] or "").strip())
            last = f"HTTP {r.status_code}: {r.text[:160]}"
            if r.status_code in (429, 500, 502, 503):
                time.sleep(min(2 ** i, 20))
                continue
            return _note(model, "")  # hard error (e.g. bad model id)
        except Exception as e:  # noqa: BLE001
            last = str(e)
            time.sleep(min(2 ** i, 20))
    sys.stderr.write(f"[warn] gen failed ({model}): {last}\n")
    return _note(model, "")


def chat(messages, model, temperature=0.7, max_tokens=600, retries=4):
    """Multi-turn completion (for the write/retrieve/act session loop)."""
    body = {"model": model, "messages": messages,
            "temperature": temperature, "max_tokens": max_tokens}
    last = None
    for i in range(retries):
        try:
            r = requests.post(BASE + "/chat/completions", headers=H, json=body, timeout=60)
            if r.status_code == 200:
                j = r.json()
                _track(j)
                return (j["choices"][0]["message"]["content"] or "").strip()
            last = f"HTTP {r.status_code}: {r.text[:160]}"
            if r.status_code in (429, 500, 502, 503):
                time.sleep(min(2 ** i, 20))
                continue
            return ""
        except Exception as e:  # noqa: BLE001
            last = str(e)
            time.sleep(min(2 ** i, 20))
    sys.stderr.write(f"[warn] chat failed ({model}): {last}\n")
    return ""


def credits():
    """Return (total_usage_usd, remaining_usd) or (None, None). Free to call."""
    try:
        r = requests.get(BASE + "/credits", headers=H, timeout=30)
        if r.status_code == 200:
            d = r.json()["data"]
            tot = float(d.get("total_credits", 0.0))
            use = float(d.get("total_usage", 0.0))
            return use, max(tot - use, 0.0)
    except Exception:
        pass
    try:
        r = requests.get(BASE + "/auth/key", headers=H, timeout=30)
        if r.status_code == 200:
            d = r.json()["data"]
            use = float(d.get("usage", 0.0))
            lim = d.get("limit")
            return use, (float(lim) - use if lim is not None else None)
    except Exception:
        pass
    return None, None


def report_cost(use0, label="run"):
    """Print spend since use0 and current balance. Call after every run."""
    use1, rem1 = credits()
    tok = (f"{USAGE['calls']} calls, "
           f"{USAGE['prompt_tokens']}+{USAGE['completion_tokens']} tokens")
    if use0 is not None and use1 is not None:
        spent = use1 - use0
        bal = f"${rem1:.4f}" if rem1 is not None else "unknown"
        print(f"[cost] {label}: ${spent:.5f} (credits delta)   {tok}   balance: {bal}")
        return spent, rem1
    print(f"[cost] {label}: credits endpoint unavailable   {tok}")
    return None, None


def parse_json(text):
    """Best-effort JSON extraction from a model response."""
    text = re.sub(r"^```(json)?|```$", "", text.strip(), flags=re.MULTILINE).strip()
    try:
        return json.loads(text)
    except Exception:
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                return None
    return None


if __name__ == "__main__":
    # Connectivity check only (FREE — no completion spend).
    use, rem = credits()
    if rem is not None:
        print(f"OpenRouter OK. used=${use:.4f}  remaining=${rem:.4f}")
    else:
        print("OpenRouter credits endpoint returned nothing (check OPENROUTER_API_KEY).")
