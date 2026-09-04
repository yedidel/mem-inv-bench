# What the earlier paper had that this one does not

Rebuilding from scratch removed the defects. It also risks removing evidence that
was sound. This is the systematic comparison.

## References: 33 of 39 dropped, and roughly ten of those matter

Six were re-keyed rather than lost (AgentPoison, MemGPT, PoisonedRAG, the
backdoor paper, Fides, CaMeL). The rest are genuine omissions, and these are the
ones that hurt:

| dropped | why it matters |
|---|---|
| **MemLineage** | THE closest competitor. The entire positioning of an origin-bound defense depends on differentiating from lineage-guided enforcement. Its absence is the single worst omission. |
| **SuperLocalMemory** | instantiates the content-trust baseline the separation result rules out. Naming the class without naming an instance weakens Table 2. |
| MemMorph, MemoryGraft, Trojan Hippo, conversational Trojan | four published attack pipelines the earlier work reproduced. Dropping them drops a distinct external-validity argument that AgentDojo does not replace. |
| Mem0, MemMachine, Generative Agents | the production memory systems that make this threat surface a standard component rather than a hypothetical |
| sleeper memory poisoning, memory control-flow attacks, memory injection | the attack literature that establishes the problem exists |
| two surveys of LLM-agent memory security | the framing allies that call for write-time provenance anchoring |
| provenance foundations (Moreau) | the endorsement log's antecedent |
| the author's own prior work on agent-protocol security | required for the cross-paper consistency rule |

## Experiments: five genuine losses, three supersessions

**Superseded, correctly.** The persistence sweep varied idle intervening
sessions, which tests dormancy. The longitudinal study replaces it with sessions
containing real completed payments, which tests history, and is the stronger
design. The unified benchmark and the cross-model trigger study both ran against
a gate that read a ground-truth origin field, so their numbers cannot be carried
over at all.

**Genuinely lost, in order of how much they cost us:**

1. **Latency and cost.** The earlier work measured the act-gate decision at
   $1.3\,\mu$s against roughly $2{,}000$\,ms for a content-judge call. This paper
   currently reports no cost vector at all, which is a direct violation of the
   rule that a deployability claim must carry latency, throughput, memory, and
   per-call cost rather than one proxy. Cheap to restore and entirely offline.

2. **Head-to-head against four published attack pipelines.** Reproducing
   attacks other people published is a different external-validity argument from
   running on someone else's benchmark, and it answers a different reviewer
   question. AgentDojo does not replace it.

3. **A consolidated ablation.** The earlier work isolated write-time binding,
   corroboration-gated elevation, and the verdict log separately. This paper has
   ablations scattered across sections and no single table, which the
   design-versus-evaluation balance rule flags: every component presented as a
   contribution must appear in at least one evaluation row.

4. **Threshold generalisation beyond $k=2$.** The earlier work swept $k$ from one
   to four against varying numbers of available vouchers. This paper fixes $k=2$
   almost everywhere. The enumerator already computes this, so restoring it costs
   nothing.

5. **The lineage default-policy probe.** Lineage gates must choose a default when
   attribution is inconclusive, and the earlier work compared default-allow
   against default-deny, showing that neither reaches acceptable security and
   utility together. That is a sharper refutation of the lineage class than
   asserting the class fails, and it belongs beside Table 2.

6. **A production memory backend.** The earlier work ran the monitor over Mem0
   with a real vector store, showing the labels survive a store that rewrites
   content during consolidation. This paper models eviction and consolidation
   formally and demonstrates neither on a real system.

7. **The whitebox trigger style.** The earlier work included an adversary that
   knows the defense and forges trust markers such as "[Finance-verified]" inside
   the untrusted payload. The current adversary model covers this in theory, and
   the empirical demonstration is gone.

8. **Attack-class breakdown.** Results were reported by class, namely sleeper,
   control-flow, direct, and data-exfiltration. The current scenarios cover these
   classes but report pooled, so a reader cannot see whether the defense behaves
   differently across them.

## Plan

Restore in this order, cheapest and most damaging first.

| item | cost | status |
|---|---|---|
| references, with the preprint pass | writing only | to do |
| latency and cost vector | offline, free | to do |
| threshold sweep over $k$ | offline, free | to do |
| lineage default-policy probe | offline, free | to do |
| consolidated ablation table | offline, free | to do |
| whitebox trigger style | one short run | to do |
| head-to-head on four published attacks | one run | to do |
| production backend | setup plus one run | optional |

Nothing from the earlier work is carried over as a number. Every restored item is
re-measured under the current harness, because the earlier harness is the one
whose defects this paper documents.
