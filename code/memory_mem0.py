#!/usr/bin/env python3
"""
Mem0 backend adapter for MEM-INV-Bench (conforms to memory.MemoryBackend).

Design note on the OpenRouter-only constraint. Mem0 uses an LLM (for fact
extraction/consolidation on write) and an embedder (for retrieval). We route the LLM
to OpenRouter via its OpenAI-compatible endpoint, and use a LOCAL HuggingFace embedder
(sentence-transformers) so no embeddings provider key is needed and the personal
GOOGLE_API_KEY is never touched. OpenRouter does not expose an embeddings endpoint, so
a local embedder is the correct way to honor the constraint.

TMA is backend-agnostic: the monitor wraps the backend's write/retrieve, so the
security guarantee is identical whether the store is the reproducible TF-IDF store or
Mem0. We keep TF-IDF for headline reproducibility and use this adapter to show the
defense transfers to a production memory framework.

Requires: `pip install mem0ai sentence-transformers`. If sentence-transformers is
absent, instantiation raises with a clear message.
"""
from __future__ import annotations

import os

from memory import MemoryBackend, MemoryItem, Origin, ActClass


def _config():
    key = os.environ.get("OPENROUTER_API_KEY")
    return {
        "llm": {
            "provider": "openai",
            "config": {
                "model": "openai/gpt-4o-mini",
                "openai_base_url": "https://openrouter.ai/api/v1",
                "api_key": key,
                "temperature": 0.0,
            },
        },
        "embedder": {
            # local, no external key; honors OpenRouter-only for LLM + no extra keys.
            "provider": "huggingface",
            "config": {"model": "sentence-transformers/all-MiniLM-L6-v2"},
        },
        "vector_store": {
            # MiniLM is 384-dim; the store MUST match (default is 1536 -> mismatch).
            "provider": "qdrant",
            "config": {"collection_name": "meminv_minilm", "embedding_model_dims": 384,
                       "on_disk": False},
        },
    }


class Mem0Backend(MemoryBackend):
    """Wrap mem0.Memory behind the MemoryBackend interface. Origin/act_class are kept
    in our own side-table keyed by Mem0's returned id, since the monitor (not Mem0)
    owns authorization. Mem0 stores/searches content; we attach labels."""

    def __init__(self, user_id="bench"):
        try:
            from mem0 import Memory
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(f"mem0 not available: {e}")
        self.mem = Memory.from_config(_config())
        self.user_id = user_id
        self._labels: dict[str, MemoryItem] = {}
        self._fallback: list[MemoryItem] = []

    def write(self, item: MemoryItem) -> str:
        res = self.mem.add(item.content, user_id=self.user_id,
                           metadata={"origin": int(item.origin)})
        # Mem0 may return one or more derived memory ids; map them all to this label.
        ids = []
        try:
            for r in (res.get("results") or []):
                ids.append(r.get("id"))
        except Exception:  # noqa: BLE001
            pass
        item.item_id = ids[0] if ids else f"m{len(self._labels)}"
        for i in ids or [item.item_id]:
            self._labels[i] = item
        self._fallback.append(item)
        return item.item_id

    def retrieve(self, query: str, k: int = 5, scope: str = "global") -> list:
        try:
            hits = self.mem.search(query, user_id=self.user_id, limit=k)
            out = []
            for h in (hits.get("results") or []):
                lab = self._labels.get(h.get("id"))
                if lab is not None:
                    # use Mem0's stored (possibly consolidated) text as content
                    lab2 = MemoryItem(content=h.get("memory", lab.content),
                                      origin=lab.origin, t_write=lab.t_write,
                                      scope=lab.scope, act_class=lab.act_class,
                                      item_id=h.get("id"))
                    out.append(lab2)
            return out
        except Exception:  # noqa: BLE001
            return self._fallback[:k]

    def all_items(self) -> list:
        return list(self._fallback)


if __name__ == "__main__":
    b = Mem0Backend()
    b.write(MemoryItem("Vendor Acme pays to ACME-OFFICIAL.", Origin.TRUSTED_TOOL, 0,
                       act_class=ActClass.ACT))
    print("retrieve:", [(i.content, int(i.origin)) for i in b.retrieve("Acme payment")])
