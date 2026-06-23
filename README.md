# MEM-INV-Bench / Non-Malleable Memory Authority (TMA-NM)

Code, formal model, and benchmark for the paper
**"Securing LLM-Agent Long-Term Memory Against Poisoning: Non-Malleable, Origin-Bound Authority with Machine-Checked Guarantees."**

- **Benchmark dataset (Hugging Face):** [https://huggingface.co/datasets/USERNAME/MEM-INV-Bench  <!-- TODO: replace USERNAME after upload -->](https://huggingface.co/datasets/anonymos-2321135/MEM-INV-Bench)
- **Paper:** (link upon publication / arXiv)

This repository is the canonical home for the **code, harness, and formal model**. The
benchmark *data* (scenarios + result logs) is also mirrored as a loadable Hugging Face
dataset at the link above.

LLM agents with persistent long-term memory are vulnerable to **memory poisoning**:
untrusted content stored now that steers a *consequential* action (payment, setting
change, data egress) in a later session. We show that defenses deciding authority from
**content** (detection / trust-scoring) or a **derivation edge** (lineage) are
*malleable*: an adversary can **launder** untrusted content so its content looks benign
and its lineage breaks or flips to "trusted." MEM-INV-Bench measures five defense classes
against three laundering channels across eight models, and ships the TLA+ separation model.

**TMA-NM** (Tamper-evident Memory Authority, Non-Malleable) binds the authority to act to a
memory item's **write-time origin**, propagates it **non-malleably**, and elevates only via
**Sybil-resistant corroboration** (at least two independent trusted principals). It reaches
**0% consequential-attack success at 100% legitimate-utility** in the unified study.

## The three laundering channels
- **L-a Self-summarization.** The agent paraphrases the poison into its own note (content
  looks benign, the derivation edge is dropped).
- **L-b Trusted-tool echo.** A trusted tool returns attacker-controlled content.
- **L-c Manufactured corroboration.** The adversary plants several untrusted items to fake
  independent consensus.

## Defense classes compared
| class | rule (see `code/laundering.py`) |
|-------|----------------------------------|
| `none` | execute as-is |
| `trust_score` / `prob_detect` | content: allow if benign-looking or two items assert the value (the latter is an LLM judge run on the model under test) |
| `lineage` | derivation edge (MemLineage-style): allow unless a live untrusted edge survives, default-allow when inconclusive |
| `capability_ifc` | single-session capability/IFC (CaMeL/Fides-style): assumes the store is clean |
| `tma_nm` (ours) | origin-bound, non-malleable: untrusted-derived stays untrusted, elevate only on two independent trusted principals |

## Layout
```
code/      reference harness + all experiment scripts (see table below)
data/      scenarios.json, scenarios_large.json,   (the benchmark scenarios + variants)
           scenarios_headtohead.json               (four published pipelines reproduced as drop-in attacks)
results/   results_*.json                          (the exact JSON logs behind the paper)
formal/    MemAuthority.tla + *.cfg                (TLA+ separation model + inductive invariant)
```

| script | produces |
|--------|----------|
| `code/benchmark.py` | unified cross-defense x channel x model study -> `results_unified.json` |
| `code/laundering.py` | the laundering matrix (witness of the separation) |
| `code/agent_bench.py` | cross-model trigger-style study and ablation -> `results.json`, `results_ablation.json` |
| `code/headtohead.py` | head-to-head vs four published poisoning pipelines -> `results_headtohead.json` |
| `code/multiturn.py` | multi-turn agentic loop (value-level taint across turns) |
| `code/mem0_eval.py` | end-to-end over a production backend (Mem0 + Qdrant + MiniLM) |
| `code/sensitivity.py` | content-judge threshold sweep (Pareto frontier) |
| `code/threshold_sweep.py` | corroboration-threshold k generalization |
| `code/stress_independence.py` | correlated/compromised-trusted stress test |
| `code/lineage_policy.py` | lineage default-allow vs default-deny probe |
| `code/latency.py` | per-decision latency microbenchmark |
| `code/check_invariant.py` | exhaustive offline check of the monitor invariant (no cost) |
| `code/test_monitor.py` | offline unit tests (no cost) |
| `code/stats.py`, `gen_tables.py`, `make_figures.py`, `per_channel_table.py` | statistics / tables / figures |

## Headline results (all from real runs; see `results/`)
- **Unified (8 models):** `tma_nm` is 0% on the direct attack and 0% on laundering at 100% legit-utility. `trust_score` is laundered (68%), `capability_ifc` also permits the direct attack (84%), and `lineage` is laundered by summarization/echo (47%).
- **Cross-model (8 models):** `tma_nm` records 0/4032 successful consequential attacks (Wilson CI [0,0.1]%), at task utility 95.9%.
- **Head-to-head vs published pipelines (8 models):** reproducing MemMorph, MemoryGraft, Trojan Hippo, and a conversational Trojan as drop-in attacks, `tma_nm` blocks all four (0/1152, 0.0%) at utility equal to undefended; `none` 38.2%, `prob_detect` 12.0%, `lineage` 19.6% (lineage gives no protection on the Trojan Hippo exfiltration, 78.5%).
- **Ablation:** removing origin binding restores attacks, removing elevation drops utility 96% -> 77%, removing the log changes neither.
- **Sensitivity:** no content-judge threshold reaches (0% ASR, 100% utility); TMA-NM does.
- **Threshold k:** auto-authorize iff independent vouchers >= k; attack ASR is 0% for every k.
- **Independence stress:** a correlated (shared-domain) compromise fools a naive count (67%) but is blocked by the domain-aware monitor (0%).
- **Production backend (Mem0):** undefended 50% vs `tma_nm` 0% (n=96/defense), legit-utility 99% for both.
- **Latency:** about 1.3 microseconds per decision, no extra model call.

## How to run
```bash
pip install -r requirements.txt
export OPENROUTER_API_KEY=sk-or-...          # LLM access is via OpenRouter only

# offline (no API key, no cost):
python code/test_monitor.py
python code/check_invariant.py

# real runs (report cost + remaining balance after each run):
python code/benchmark.py --trials 8
python code/headtohead.py --trials 6     # vs MemMorph, MemoryGraft, Trojan Hippo, conversational Trojan
python code/laundering.py
python code/sensitivity.py
python code/threshold_sweep.py
python code/stress_independence.py
python code/lineage_policy.py
python code/multiturn.py
python code/mem0_eval.py        # needs: pip install mem0ai sentence-transformers qdrant-client
```
All LLM access is routed through **OpenRouter** (OpenAI-compatible REST). No numbers in the
paper or `results/` are fabricated; every metric comes from a logged run.

## Formal model
`formal/MemAuthority.tla` encodes the write->retrieve->act pipeline with a laundering
adversary and a defense-independent security invariant. Check with TLC (download
`tla2tools.jar`, see `formal/DOWNLOAD_TLA.md`):
```bash
java -jar tla2tools.jar -config formal/MA_content.cfg      formal/MemAuthority.tla   # T1: violated
java -jar tla2tools.jar -config formal/MA_lineage.cfg      formal/MemAuthority.tla   # T1: violated
java -jar tla2tools.jar -config formal/MA_nonmalleable.cfg formal/MemAuthority.tla   # T3: holds
java -jar tla2tools.jar -config formal/MA_ind.cfg          formal/MemAuthority.tla   # inductive invariant
```

## Uploading / releasing
See `UPLOAD_GITHUB.md` for pushing this repo to GitHub and `UPLOAD_HF.md` for publishing
the benchmark data as a Hugging Face dataset.

## Intended use and ethics
This is a **defensive** security artifact for research and evaluation of agent-memory
defenses. The attack scenarios are synthetic, target fictitious accounts and recipients,
and exist to measure defenses. Do not use them against systems you are not authorized to test.

## Citation
```bibtex
@misc{louck2026nonmalleable,
  title  = {Securing LLM-Agent Long-Term Memory Against Poisoning: Non-Malleable,
            Origin-Bound Authority with Machine-Checked Guarantees},
  author = {Yedidel Louck},
  year   = {2026},
  note   = {Under review at IEEE Transactions on Dependable and Secure Computing}
}
```

## License
MIT (see `LICENSE`).
