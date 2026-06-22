#!/usr/bin/env python3
"""
Temporal Memory Authorization monitor.

This is the trusted reference monitor that mediates the write -> retrieve -> act
pipeline. It enforces the central invariant:

  INV (Action Integrity): no consequential action is *caused by* a memory item
  whose effective act_class < ACT, unless a fresh user authorization bound to that
  specific action is present.

Three mechanisms (each independently ablatable in the benchmark):
  M1 write-time action binding  : act_class fixed at write time from origin.
  M2 corroboration-gated elevation: act_class can rise ONLY via independent trusted
                                    corroboration or a fresh action-bound user OK.
  M3 tamper-evident log         : append-only hash chain; origin labels cannot be
                                    retroactively forged and any compromise is
                                    auditable.

The Python monitor is the executable spec; the TLA+/Alloy model (formal/) checks
INV holds for all reachable states.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional

from memory import (MemoryBackend, MemoryItem, Origin, ActClass,
                    bind_act_class)


@dataclass
class UserAuthorization:
    """A fresh user confirmation BOUND to one specific action. Not transferable to
    a different action and (optionally) single-use within one session."""
    action_signature: str   # canonical hash of the action being approved
    session: int
    consumed: bool = False


@dataclass
class LogEntry:
    seq: int
    op: str                 # "write" | "elevate" | "act_allow" | "act_deny"
    payload: dict
    prev_hash: str
    this_hash: str = ""

    def compute_hash(self) -> str:
        body = json.dumps({"seq": self.seq, "op": self.op,
                           "payload": self.payload, "prev_hash": self.prev_hash},
                          sort_keys=True)
        return hashlib.sha256(body.encode()).hexdigest()


def action_signature(action: dict) -> str:
    """Canonical signature of a consequential action (tool + key args)."""
    return hashlib.sha256(json.dumps(action, sort_keys=True).encode()).hexdigest()


class MemoryMonitor:
    def __init__(self, backend: MemoryBackend, *,
                 enable_binding=True, enable_elevation=True, enable_log=True):
        self.backend = backend
        # ablation switches
        self.enable_binding = enable_binding
        self.enable_elevation = enable_elevation
        self.enable_log = enable_log
        self.session = 0
        self._log: list[LogEntry] = []
        self._genesis = "0" * 64

    # -- session clock -----------------------------------------------------
    def new_session(self) -> int:
        self.session += 1
        return self.session

    # -- M3 tamper-evident log --------------------------------------------
    def _append_log(self, op: str, payload: dict):
        if not self.enable_log:
            return
        prev = self._log[-1].this_hash if self._log else self._genesis
        e = LogEntry(seq=len(self._log), op=op, payload=payload, prev_hash=prev)
        e.this_hash = e.compute_hash()
        self._log.append(e)

    def verify_log(self) -> bool:
        """Re-derive the hash chain; any retroactive edit breaks it."""
        prev = self._genesis
        for e in self._log:
            if e.prev_hash != prev or e.compute_hash() != e.this_hash:
                return False
            prev = e.this_hash
        return True

    # -- M1 write-time binding --------------------------------------------
    def write(self, content: str, origin: Origin, scope: str = "global",
              meta: Optional[dict] = None) -> MemoryItem:
        if self.enable_binding:
            act = bind_act_class(origin)
        else:
            # ablation: no binding -> everything is treated as actionable (the
            # "naive memory" condition the attacks exploit).
            act = ActClass.ACT
        item = MemoryItem(content=content, origin=origin, t_write=self.session,
                          scope=scope, act_class=act, meta=meta or {})
        self.backend.write(item)
        self._append_log("write", {"item_id": item.item_id, "origin": int(origin),
                                   "act_class": int(act), "t_write": item.t_write,
                                   "content_sha": hashlib.sha256(content.encode()).hexdigest()[:16]})
        return item

    # -- M2 corroboration-gated elevation ---------------------------------
    def elevate(self, item: MemoryItem, *, corroborators: Optional[list] = None,
                user_auth: Optional[UserAuthorization] = None,
                target: ActClass = ActClass.ACT) -> bool:
        """Raise an item's authority ONLY through independent trusted corroboration
        or a fresh action-bound user OK. An item can never elevate itself."""
        if not self.enable_elevation:
            return False
        corroborators = corroborators or []
        # independent corroboration: >=2 distinct trusted-origin items, none being
        # the item itself, supporting the same claim.
        trusted = [c for c in corroborators
                   if c.item_id != item.item_id
                   and c.origin >= Origin.TRUSTED_TOOL]
        independent = len({c.item_id for c in trusted}) >= 2
        if independent:
            item.act_class = max(item.act_class, target)
            item.corroborations = [c.item_id for c in trusted]
            self._append_log("elevate", {"item_id": item.item_id,
                                         "via": "corroboration",
                                         "by": item.corroborations,
                                         "to": int(item.act_class)})
            return True
        if user_auth is not None and not user_auth.consumed:
            item.act_class = max(item.act_class, target)
            self._append_log("elevate", {"item_id": item.item_id,
                                         "via": "user_auth",
                                         "to": int(item.act_class)})
            return True
        return False

    # -- act-time enforcement (the invariant) -----------------------------
    def authorize_action(self, action: dict, supporting_items: list,
                         user_auth: Optional[UserAuthorization] = None) -> tuple:
        """Decide allow/deny for a consequential action.

        Allow iff EVERY supporting item that the action causally depends on has
        effective act_class == ACT, OR a fresh user authorization bound to THIS
        action is present (and gets consumed). Returns (allowed, reason)."""
        sig = action_signature(action)
        fresh_ok = (user_auth is not None and not user_auth.consumed
                    and user_auth.action_signature == sig)
        blockers = [it for it in supporting_items if it.act_class < ActClass.ACT]
        if not blockers:
            self._append_log("act_allow", {"sig": sig[:16], "reason": "all_authorized"})
            return True, "all supporting memory is ACT-authorized"
        if fresh_ok:
            user_auth.consumed = True
            self._append_log("act_allow", {"sig": sig[:16], "reason": "fresh_user_auth"})
            return True, "fresh action-bound user authorization"
        self._append_log("act_deny", {"sig": sig[:16],
                                      "blockers": [b.item_id for b in blockers]})
        return False, f"blocked: {len(blockers)} sub-ACT item(s) drive this action"

    # -- audit -------------------------------------------------------------
    def log_records(self) -> list:
        return [{"seq": e.seq, "op": e.op, "payload": e.payload,
                 "hash": e.this_hash[:16]} for e in self._log]
