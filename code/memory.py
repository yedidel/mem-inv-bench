#!/usr/bin/env python3
"""
Memory model for MEM-INV-Bench.

A memory item is (content, origin, scope, t_write, act_class). The novel core of
the defense lives here: act_class is bound to the item AT WRITE TIME as a function
of its origin, and is enforced on every later retrieval/act regardless of when or
how the item is retrieved (the temporal dimension).

Backends are swappable behind MemoryBackend so the same monitor/agent loop runs
over a toy vector store now and over Mem0/Letta later.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Optional


class Origin(IntEnum):
    """Trust class of where a memory item came from. Set by the trusted monitor;
    the adversary cannot forge it (threat model, Section 3)."""
    USER = 3            # the human principal, via the authorization channel
    TRUSTED_TOOL = 2    # a tool/source on the trusted registry
    AGENT = 1           # the agent's own derived notes
    UNTRUSTED_EXTERNAL = 0  # documents, web pages, tool output, other users


class ActClass(IntEnum):
    """Authority a memory item carries to influence the act stage."""
    NONE = 0     # may inform a response, may NOT cause a consequential action
    INFORM = 1   # may be surfaced (with provenance); still may not act
    ACT = 2      # may cause a consequential action (tool call, payment, exec)


# Write-time binding policy: origin -> default authority. This is the mechanism
# that makes dormancy and trigger-disguise irrelevant — authority is decided here,
# at write time, not later from content.
DEFAULT_ACT_CLASS = {
    Origin.USER: ActClass.ACT,
    Origin.TRUSTED_TOOL: ActClass.ACT,
    Origin.AGENT: ActClass.INFORM,
    Origin.UNTRUSTED_EXTERNAL: ActClass.NONE,
}


@dataclass
class MemoryItem:
    content: str
    origin: Origin
    t_write: int                      # logical session index at write time
    scope: str = "global"             # which sessions/agents/tools may read it
    act_class: ActClass = ActClass.NONE
    item_id: Optional[str] = None
    # corroboration: ids of independent trusted items that support this one.
    corroborations: list = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    def to_record(self):
        d = asdict(self)
        d["origin"] = int(self.origin)
        d["act_class"] = int(self.act_class)
        return d


def bind_act_class(origin: Origin) -> ActClass:
    """Write-time action binding (the novel core). Authority is a function of
    origin only — never of the item's content or phrasing."""
    return DEFAULT_ACT_CLASS[origin]


# ---------------------------------------------------------------------------
# Swappable retrieval backend
# ---------------------------------------------------------------------------
class MemoryBackend:
    """Interface every backend implements. write/retrieve only; authorization is
    the monitor's job, not the store's, so backends stay swappable (toy -> Mem0)."""

    def write(self, item: MemoryItem) -> str:  # returns item_id
        raise NotImplementedError

    def retrieve(self, query: str, k: int = 5, scope: str = "global") -> list:
        raise NotImplementedError

    def all_items(self) -> list:
        raise NotImplementedError


_WORD = re.compile(r"[a-z0-9]+")


def _tokens(text: str):
    return _WORD.findall(text.lower())


class SimpleVectorBackend(MemoryBackend):
    """Dependency-free TF-IDF cosine retriever. Real enough for a long-term store
    (vector store + retrieval) without pinning a heavy embedding model; the
    Mem0/Letta adapter (memory_mem0.py) implements the same interface for the
    headline results. Deterministic, which keeps the benchmark reproducible."""

    def __init__(self):
        self._items: list[MemoryItem] = []
        self._tf: list[Counter] = []
        self._df: Counter = Counter()
        self._n = 0

    def write(self, item: MemoryItem) -> str:
        if item.item_id is None:
            item.item_id = f"m{len(self._items)}"
        toks = _tokens(item.content)
        tf = Counter(toks)
        self._items.append(item)
        self._tf.append(tf)
        for t in set(toks):
            self._df[t] += 1
        self._n += 1
        return item.item_id

    def _idf(self, term):
        return math.log((1 + self._n) / (1 + self._df.get(term, 0))) + 1.0

    def _vec(self, tf: Counter):
        return {t: c * self._idf(t) for t, c in tf.items()}

    @staticmethod
    def _cos(a: dict, b: dict):
        if not a or not b:
            return 0.0
        common = set(a) & set(b)
        num = sum(a[t] * b[t] for t in common)
        na = math.sqrt(sum(v * v for v in a.values()))
        nb = math.sqrt(sum(v * v for v in b.values()))
        return num / (na * nb) if na and nb else 0.0

    def retrieve(self, query: str, k: int = 5, scope: str = "global") -> list:
        qv = self._vec(Counter(_tokens(query)))
        scored = []
        for item, tf in zip(self._items, self._tf):
            if scope != "global" and item.scope not in ("global", scope):
                continue
            scored.append((self._cos(qv, self._vec(tf)), item))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [it for s, it in scored[:k] if s > 0.0]

    def all_items(self) -> list:
        return list(self._items)
